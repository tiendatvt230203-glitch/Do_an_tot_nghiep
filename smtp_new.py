import asyncio, smtplib, re, subprocess
from aiosmtpd.controller import Controller
from email import message_from_bytes
from email.utils import parseaddr
from datetime import datetime
from sqlalchemy import create_engine, text
import spf
import dkim
import dns.resolver
import json

# Import malware scanner module
try:
    from malware_scanner import scan_attachment, calculate_file_hash
    MALWARE_SCANNER_AVAILABLE = True
    print("[INFO] Malware scanner module loaded successfully")
except ImportError as e:
    MALWARE_SCANNER_AVAILABLE = False
    print(f"[WARNING] Malware scanner not available: {e}")

engine = create_engine("postgresql://postgres@localhost/email_gateway")

SPAM_THRESHOLD = 5.0  # Emails with score > 5.0 are considered spam

def check_spam(email_content, spam_threshold=5.0):
    """
    Check spam using SpamAssassin spamc client
    Returns: (spam_score, is_spam)
    spam_threshold: custom threshold for this domain
    """
    try:
        result = subprocess.run(
            ['spamc', '-c'],
            input=email_content,
            capture_output=True,
            timeout=30
        )
        output = result.stdout.decode('utf-8', errors='ignore').strip()

        if '/' in output:
            score_str = output.split('/')[0].strip()
            try:
                spam_score = float(score_str)
            except:
                spam_score = 0.0
        else:
            spam_score = 0.0

        is_spam = spam_score > spam_threshold
        print(f"  [SPAM CHECK] Score: {spam_score:.2f}, Threshold: {spam_threshold} → {'SPAM' if is_spam else 'SAFE'}")
        return (spam_score, is_spam)

    except Exception as e:
        print(f"  [SPAM CHECK ERROR] {e}")
        return (0.0, False)

def check_spf(sender_ip, from_addr, helo_name='unknown'):
    """Check SPF record"""
    try:
        result, explanation = spf.check2(i=sender_ip, s=from_addr, h=helo_name)
        print(f"  [SPF] Result: {result}")
        return result
    except Exception as e:
        print(f"  [SPF ERROR] {e}")
        return 'none'

def check_dkim(email_bytes):
    """Check DKIM signature"""
    try:
        result = dkim.verify(email_bytes)
        status = 'pass' if result else 'fail'
        print(f"  [DKIM] Result: {status}")
        return status
    except Exception as e:
        print(f"  [DKIM ERROR] {e}")
        return 'none'

def check_dmarc(from_domain):
    """Check DMARC policy"""
    try:
        dmarc_domain = f'_dmarc.{from_domain}'
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=DMARC1'):
                if 'p=reject' in txt:
                    result = 'reject'
                elif 'p=quarantine' in txt:
                    result = 'quarantine'
                else:
                    result = 'none'
                print(f"  [DMARC] Policy: {result}")
                return result
        print(f"  [DMARC] No policy found")
        return 'none'
    except Exception as e:
        print(f"  [DMARC] Not configured")
        return 'none'

def extract_attachments(msg):
    """
    Extract all attachments from email message
    Returns: list of {filename, content, size, mime_type}
    """
    attachments = []

    try:
        for part in msg.walk():
            # Check if part is attachment
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename() or 'unknown'
                content = part.get_payload(decode=True)

                if content:
                    attachments.append({
                        'filename': filename,
                        'content': content,
                        'size': len(content),
                        'mime_type': part.get_content_type()
                    })

    except Exception as e:
        print(f"  [ATTACHMENT ERROR] Failed to extract attachments: {e}")

    return attachments

def check_rules(from_addr, to_addr, subject, body, sender_ip, conn):
    """
    Check blacklist/whitelist rules
    Returns: (action, rule_id, reason)
    action: 'block', 'allow', 'continue'
    """
    domain = to_addr.split('@')[1] if '@' in to_addr else ''

    rules_query = text("""
        SELECT id, rule_type, scope_type, scope_value, filter_field, match_type, match_value, priority
        FROM filter_rules
        WHERE is_active = true
        AND (
            scope_type = 'common'
            OR (scope_type = 'domain' AND scope_value = :domain)
            OR (scope_type = 'mail_address' AND scope_value = :mail)
        )
        ORDER BY priority DESC, id ASC
    """)

    rules = conn.execute(rules_query, {"domain": domain, "mail": to_addr}).fetchall()

    for rule in rules:
        rule_id, rule_type, scope_type, scope_value, filter_field, match_type, match_value, priority = rule

        check_value = ""
        if filter_field == "subject":
            check_value = subject or ""
        elif filter_field == "mail_address":
            check_value = from_addr or ""
        elif filter_field == "sender_domain":
            check_value = from_addr.split('@')[1] if '@' in from_addr else ""
        elif filter_field == "body":
            check_value = body or ""
        elif filter_field == "ip":
            check_value = sender_ip or ""

        matched = False
        try:
            if match_type == "match":
                matched = (check_value == match_value)
            elif match_type == "include":
                matched = (match_value in check_value)
            elif match_type == "start":
                matched = check_value.startswith(match_value)
            elif match_type == "end":
                matched = check_value.endswith(match_value)
            elif match_type == "regex":
                matched = bool(re.search(match_value, check_value, re.IGNORECASE))
        except Exception as e:
            print(f"  [RULE ERROR] Rule {rule_id}: {e}")
            continue

        if matched:
            scope_desc = f"{scope_type}={scope_value}" if scope_value else scope_type
            print(f"  [RULE MATCH] Rule #{rule_id} ({rule_type}/{scope_desc}): {filter_field} {match_type} '{match_value}'")

            if rule_type == "whitelist":
                reason = f"Whitelisted by rule #{rule_id}: {filter_field} {match_type} '{match_value}' (scope: {scope_desc})"
                return ('allow', rule_id, reason)
            elif rule_type == "blacklist":
                reason = f"Blocked by rule #{rule_id}: {filter_field} {match_type} '{match_value}' (scope: {scope_desc})"
                return ('block', rule_id, reason)

    return ('continue', None, None)

class Gateway:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        print(f"[RCPT] Checking: {address}")
        if '@' not in address:
            print(f"[RCPT] REJECT: Invalid address")
            return '550 Invalid address'
        domain = address.split('@')[1].lower()
        try:
            with engine.connect() as conn:
                result = conn.execute(text("SELECT id FROM domains WHERE domain_name = :d AND is_active = true"), {"d": domain})
                if not result.fetchone():
                    print(f"[RCPT] REJECT: Domain {domain} not configured")
                    return f'550 Domain {domain} not configured'
            envelope.rcpt_tos.append(address)
            print(f"[RCPT] ACCEPT: {address}")
            return '250 OK'
        except Exception as e:
            print(f"[RCPT] ERROR: {e}")
            return '451 Error'

    async def handle_DATA(self, server, session, envelope):
        print(f"\n{'='*70}")
        print(f"[EMAIL] NEW EMAIL RECEIVED!")
        print(f"{'='*70}")
        try:
            msg = message_from_bytes(envelope.content)
            subject = msg.get('Subject', '(No subject)')
            from_addr = parseaddr(msg.get('From', ''))[1] or envelope.mail_from
            message_id = msg.get('Message-ID', f'<{datetime.now().timestamp()}@gw>')
            sender_ip = session.peer[0] if session.peer else 'unknown'

            # Extract body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                        except:
                            pass
            else:
                try:
                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    body = ""

            print(f"From: {from_addr}")
            print(f"To: {envelope.rcpt_tos}")
            print(f"Subject: {subject}")
            print(f"Sender IP: {sender_ip}")
            print(f"Message-ID: {message_id}")
            print(f"{'-'*70}")

            for to_addr in envelope.rcpt_tos:
                domain = to_addr.split('@')[1]
                print(f"[PROCESSING] {to_addr}")

                try:
                    with engine.connect() as conn:
                        result = conn.execute(text("SELECT id, backend_server, backend_port, spam_threshold FROM domains WHERE domain_name = :d"), {"d": domain})
                        row = result.fetchone()
                        if not row:
                            print(f"  [ERROR] Domain not found in DB")
                            continue

                        domain_id, backend_server, backend_port, spam_threshold = row[0], row[1], row[2], row[3] if row[3] is not None else 5.0
                        print(f"  [INFO] Domain ID: {domain_id}, Backend: {backend_server}:{backend_port}, Spam Threshold: {spam_threshold}")

                        # STEP 1: CHECK BLACKLIST/WHITELIST RULES
                        print(f"  [FILTER] Checking blacklist/whitelist rules...")
                        action, rule_id, reason = check_rules(from_addr, to_addr, subject, body, sender_ip, conn)

                        if action == 'block':
                            # BLACKLIST MATCHED - Block immediately
                            print(f"  [BLOCKED] {reason}")
                            conn.execute(text("""
                                INSERT INTO emails (domain_id, message_id, subject, from_address, to_address, sender_ip, body, status, block_reason, matched_rule_id, spam_result)
                                VALUES (:a, :b, :c, :d, :e, :f, :g, 'blocked', :h, :i, 'skipped')
                            """), {"a": domain_id, "b": message_id, "c": subject, "d": from_addr, "e": to_addr, "f": sender_ip, "g": body[:5000], "h": reason, "i": rule_id})
                            conn.commit()
                            continue

                        elif action == 'allow':
                            # WHITELIST MATCHED - But still check SPF to prevent spoofing
                            print(f"  [WHITELISTED] {reason}")
                            print(f"  [SECURITY] Checking SPF to prevent domain spoofing...")

                            spf_result = check_spf(sender_ip, from_addr)

                            # SPF must be PASS for whitelisted domains - anything else is suspicious
                            if spf_result != 'pass':
                                block_msg = f"SUSPICIOUS EMAIL from whitelisted domain! SPF {spf_result.upper()} - Only SPF PASS is allowed for whitelisted domains. Sender IP {sender_ip}"
                                print(f"  [BLOCKED] {block_msg}")
                                conn.execute(text("""
                                    INSERT INTO emails (domain_id, message_id, subject, from_address, to_address, sender_ip, body, status, block_reason, matched_rule_id, spam_result, spf_result)
                                    VALUES (:a, :b, :c, :d, :e, :f, :g, 'blocked', :h, :i, 'spoofed', :j)
                                """), {"a": domain_id, "b": message_id, "c": subject, "d": from_addr, "e": to_addr, "f": sender_ip, "g": body[:5000], "h": block_msg, "i": rule_id, "j": spf_result})
                                conn.commit()
                                continue

                            # SPF PASS - Safe to deliver
                            print(f"  [SPF VERIFIED] PASS - Email is authentic from authorized server")
                            print(f"  [INFO] Skipping spam/DKIM/DMARC checks for verified whitelisted email")

                            conn.execute(text("""
                                INSERT INTO emails (domain_id, message_id, subject, from_address, to_address, sender_ip, body, status, block_reason, matched_rule_id, spam_result, spf_result)
                                VALUES (:a, :b, :c, :d, :e, :f, :g, 'processing', :h, :i, 'skipped', :j)
                            """), {"a": domain_id, "b": message_id, "c": subject, "d": from_addr, "e": to_addr, "f": sender_ip, "g": body[:5000], "h": reason, "i": rule_id, "j": spf_result})
                            conn.commit()

                            email_id = conn.execute(text("SELECT id FROM emails WHERE message_id = :m ORDER BY id DESC LIMIT 1"), {"m": message_id}).fetchone()[0]

                            print(f"  [FORWARD] Delivering to {backend_server}:{backend_port}...")
                            try:
                                smtp = smtplib.SMTP(backend_server, backend_port, timeout=30)
                                smtp.sendmail(envelope.mail_from, [to_addr], envelope.content)
                                smtp.quit()
                                conn.execute(text("UPDATE emails SET status = 'delivered' WHERE id = :i"), {"i": email_id})
                                conn.commit()
                                print(f"  [SUCCESS] Delivered!")
                            except Exception as delivery_err:
                                print(f"  [DELIVERY ERROR] {delivery_err}")
                                conn.execute(text("UPDATE emails SET status = 'failed' WHERE id = :i"), {"i": email_id})
                                conn.commit()
                            continue

                        # STEP 2: NO MATCH - Check Spam
                        print(f"  [FILTER] No blacklist/whitelist match - Checking spam...")
                        spam_score, is_spam = check_spam(envelope.content, spam_threshold)
                        spam_result = 'spam' if is_spam else 'safe'

                        if is_spam:
                            print(f"  [SPAM DETECTED] Score: {spam_score:.2f} > Threshold: {spam_threshold}")
                            conn.execute(text("""
                                INSERT INTO emails (domain_id, message_id, subject, from_address, to_address, sender_ip, body, status, block_reason, spam_score, spam_result)
                                VALUES (:a, :b, :c, :d, :e, :f, :g, 'spam', :h, :i, 'spam')
                            """), {"a": domain_id, "b": message_id, "c": subject, "d": from_addr, "e": to_addr, "f": sender_ip, "g": body[:5000], "h": f"Spam score {spam_score:.2f} exceeds threshold {spam_threshold}", "i": spam_score})
                            conn.commit()
                            continue

                        # STEP 3: Spam passed - Check SPF/DKIM/DMARC
                        print(f"  [SPAM CHECK PASSED] Score: {spam_score:.2f} - Checking SPF/DKIM/DMARC...")
                        spf_result = check_spf(sender_ip, from_addr)
                        dkim_result = check_dkim(envelope.content)
                        from_domain = from_addr.split('@')[1] if '@' in from_addr else ''
                        dmarc_result = check_dmarc(from_domain)

                        # STEP 3.5: Calculate Authentication Penalty
                        auth_penalty = 0.0
                        if spf_result == 'fail':
                            auth_penalty += 5.0
                            print(f"  [AUTH PENALTY] SPF FAIL → +5.0 points")
                        elif spf_result == 'softfail':
                            auth_penalty += 1.5
                            print(f"  [AUTH PENALTY] SPF SOFTFAIL → +1.5 points")

                        if dkim_result == 'fail':
                            auth_penalty += 5.0
                            print(f"  [AUTH PENALTY] DKIM FAIL → +5.0 points")

                        if dmarc_result == 'reject':
                            auth_penalty += 2.5
                            print(f"  [AUTH PENALTY] DMARC REJECT → +2.5 points")
                        elif dmarc_result == 'quarantine':
                            auth_penalty += 1.5
                            print(f"  [AUTH PENALTY] DMARC QUARANTINE → +1.5 points")

                        # Add penalty to spam score
                        final_spam_score = spam_score + auth_penalty
                        if auth_penalty > 0:
                            print(f"  [TOTAL SCORE] Base: {spam_score:.2f} + Penalty: {auth_penalty:.2f} = {final_spam_score:.2f}")

                        # Check if final score exceeds threshold
                        if final_spam_score > spam_threshold:
                            print(f"  [BLOCKED] Final score {final_spam_score:.2f} exceeds threshold {spam_threshold}")
                            conn.execute(text("""
                                INSERT INTO emails (domain_id, message_id, subject, from_address, to_address, sender_ip, body, status, block_reason, spam_score, spam_result, spf_result, dkim_result, dmarc_result)
                                VALUES (:a, :b, :c, :d, :e, :f, :g, 'spam', :h, :i, 'spam', :j, :k, :l)
                            """), {"a": domain_id, "b": message_id, "c": subject, "d": from_addr, "e": to_addr, "f": sender_ip, "g": body[:5000], "h": f"Final spam score {final_spam_score:.2f} (base {spam_score:.2f} + auth penalty {auth_penalty:.2f}) exceeds threshold {spam_threshold}", "i": final_spam_score, "j": spf_result, "k": dkim_result, "l": dmarc_result})
                            conn.commit()
                            continue

                        conn.execute(text("""
                            INSERT INTO emails (domain_id, message_id, subject, from_address, to_address, sender_ip, body, status, spam_score, spam_result, spf_result, dkim_result, dmarc_result)
                            VALUES (:a, :b, :c, :d, :e, :f, :g, 'processing', :h, :i, :j, :k, :l)
                        """), {"a": domain_id, "b": message_id, "c": subject, "d": from_addr, "e": to_addr, "f": sender_ip, "g": body[:5000], "h": final_spam_score, "i": spam_result, "j": spf_result, "k": dkim_result, "l": dmarc_result})
                        conn.commit()

                        email_id = conn.execute(text("SELECT id FROM emails WHERE message_id = :m ORDER BY id DESC LIMIT 1"), {"m": message_id}).fetchone()[0]
                        print(f"  [SAVED] Database ID: {email_id}")

                        # STEP 4: Scan Attachments for Malware
                        if MALWARE_SCANNER_AVAILABLE:
                            attachments = extract_attachments(msg)

                            if attachments:
                                print(f"  [ATTACHMENTS] Found {len(attachments)} attachment(s)")
                                conn.execute(text("UPDATE emails SET has_attachments = true WHERE id = :i"), {"i": email_id})
                                conn.commit()

                                malware_found = False

                                for att in attachments:
                                    print(f"    📎 {att['filename']} ({att['size']} bytes, {att['mime_type']})")

                                    # Scan with ClamAV + VirusTotal
                                    scan_result = scan_attachment(
                                        att['content'],
                                        att['filename'],
                                        att['mime_type']
                                    )

                                    # Save attachment info to database
                                    conn.execute(text("""
                                        INSERT INTO email_attachments (
                                            email_id, filename, file_size, file_hash, mime_type,
                                            clamav_scanned, clamav_result, clamav_virus_name, clamav_scan_time,
                                            virustotal_scanned, virustotal_malicious, virustotal_total,
                                            virustotal_permalink, virustotal_threat_names, virustotal_scan_time,
                                            is_malware, scan_status
                                        ) VALUES (
                                            :email_id, :filename, :file_size, :file_hash, :mime_type,
                                            :clamav_scanned, :clamav_result, :clamav_virus_name, :clamav_scan_time,
                                            :vt_scanned, :vt_malicious, :vt_total,
                                            :vt_permalink, :vt_threats, :vt_scan_time,
                                            :is_malware, :scan_status
                                        )
                                    """), {
                                        "email_id": email_id,
                                        "filename": att['filename'],
                                        "file_size": att['size'],
                                        "file_hash": scan_result['file_hash'],
                                        "mime_type": att['mime_type'],
                                        "clamav_scanned": scan_result['clamav'] is not None,
                                        "clamav_result": scan_result['clamav']['result'] if scan_result['clamav'] else None,
                                        "clamav_virus_name": scan_result['clamav']['virus_name'] if scan_result['clamav'] else None,
                                        "clamav_scan_time": scan_result['clamav']['scan_time'] if scan_result['clamav'] else None,
                                        "vt_scanned": scan_result['virustotal'] is not None and scan_result['virustotal']['scanned'],
                                        "vt_malicious": scan_result['virustotal']['malicious'] if scan_result['virustotal'] else 0,
                                        "vt_total": scan_result['virustotal']['total'] if scan_result['virustotal'] else 0,
                                        "vt_permalink": scan_result['virustotal']['permalink'] if scan_result['virustotal'] else None,
                                        "vt_threats": json.dumps(scan_result['virustotal']['threat_names']) if scan_result['virustotal'] else None,
                                        "vt_scan_time": scan_result['virustotal']['scan_time'] if scan_result['virustotal'] else None,
                                        "is_malware": scan_result['is_malware'],
                                        "scan_status": 'infected' if scan_result['is_malware'] else 'clean'
                                    })
                                    conn.commit()

                                    # Check if malware detected
                                    if scan_result['is_malware']:
                                        malware_found = True
                                        print(f"    ❌ MALWARE DETECTED!")

                                # Update email status
                                conn.execute(text("UPDATE emails SET attachments_scanned = true, malware_detected = :m WHERE id = :i"),
                                           {"m": malware_found, "i": email_id})
                                conn.commit()

                                # Block email if malware found
                                if malware_found:
                                    print(f"  [BLOCKED] Email contains malware in attachments!")
                                    conn.execute(text("UPDATE emails SET status = 'blocked', block_reason = :r WHERE id = :i"),
                                               {"r": "Malware detected in attachment(s)", "i": email_id})
                                    conn.commit()
                                    continue

                                print(f"  [ATTACHMENTS] All clean ✓")
                            else:
                                # No attachments
                                conn.execute(text("UPDATE emails SET has_attachments = false, attachments_scanned = true WHERE id = :i"), {"i": email_id})
                                conn.commit()

                        # STEP 5: All checks passed - Deliver
                        print(f"  [FORWARD] Delivering to {backend_server}:{backend_port}...")
                        try:
                            smtp = smtplib.SMTP(backend_server, backend_port, timeout=30)
                            smtp.sendmail(envelope.mail_from, [to_addr], envelope.content)
                            smtp.quit()
                            conn.execute(text("UPDATE emails SET status = 'delivered' WHERE id = :i"), {"i": email_id})
                            conn.commit()
                            print(f"  [SUCCESS] Delivered!")
                        except Exception as delivery_err:
                            print(f"  [DELIVERY ERROR] {delivery_err}")
                            conn.execute(text("UPDATE emails SET status = 'failed' WHERE id = :i"), {"i": email_id})
                            conn.commit()

                except Exception as e:
                    print(f"  [ERROR] {e}")
                    import traceback
                    traceback.print_exc()

            print(f"{'='*70}\n")
            return '250 Message accepted'

        except Exception as e:
            print(f"[CRITICAL ERROR] {e}")
            import traceback
            traceback.print_exc()
            return '451 Internal error'

if __name__ == '__main__':
    print("\n" + "="*70)
    print("  SMTP SERVER WITH SPAM FILTERING")
    print("="*70)
    print("  Listening on: 0.0.0.0:25")
    print("  Spam Threshold: 5.0")
    print("  Press Ctrl+C to stop")
    print("="*70 + "\n")

    controller = Controller(Gateway(), hostname='0.0.0.0', port=25)
    controller.start()
    asyncio.get_event_loop().run_forever()
