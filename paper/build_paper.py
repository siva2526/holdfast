#!/usr/bin/env python3
"""Builds the paper (Word) from the result data in ../eval/results. Needs python-docx; convert to PDF with LibreOffice if wanted.
Usage: python3 build_paper.py [--url https://github.com/USER/holdfast]      (the URL is printed in the paper; default is a highlighted placeholder)"""
import os, sys, argparse
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
_ap = argparse.ArgumentParser(); _ap.add_argument('--url', default=''); _args = _ap.parse_args()
CODE_URL = _args.url or '[[https://github.com/USERNAME/holdfast]]'
RESULTS = os.path.join(HERE, '..', 'eval', 'results')
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

doc = Document()
sec = doc.sections[0]
sec.left_margin = sec.right_margin = Inches(1); sec.top_margin = sec.bottom_margin = Inches(1)
st = doc.styles['Normal']; st.font.name = 'Times New Roman'; st.font.size = Pt(11)
st.element.rPr.rFonts.set(qn('w:eastAsia'), 'Times New Roman')
st.paragraph_format.space_after = Pt(6)
for name, size in (('Heading 1', 14), ('Heading 2', 12)):
    h = doc.styles[name]; h.font.name = 'Times New Roman'; h.font.size = Pt(size); h.font.bold = True
    h.font.color.rgb = RGBColor(0, 0, 0); h.element.rPr.rFonts.set(qn('w:eastAsia'), 'Times New Roman')
    h.paragraph_format.space_before = Pt(12); h.paragraph_format.space_after = Pt(4)

def shade(run, color='FFFF00'):
    rPr = run._r.get_or_add_rPr(); shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear'); shd.set(qn('w:color'), 'auto'); shd.set(qn('w:fill'), color); rPr.append(shd)

def para(text='', bold=False, italic=False, align=None, size=None, style=None):
    p = doc.add_paragraph(style=style)
    add_runs(p, text, bold, italic, size)
    if align: p.alignment = align
    return p

def add_runs(p, text, bold=False, italic=False, size=None):
    # markup: **bold**, `code`, [[todo]]
    import re
    for tok in re.split(r'(\*\*.+?\*\*|`.+?`|\[\[.+?\]\])', text):
        if not tok: continue
        if tok.startswith('**'): r = p.add_run(tok[2:-2]); r.bold = True
        elif tok.startswith('`'): r = p.add_run(tok[1:-1]); r.font.name = 'Courier New'; r.font.size = Pt(9.5)
        elif tok.startswith('[['): r = p.add_run('[' + tok[2:-2] + ']'); shade(r)
        else: r = p.add_run(tok)
        if bold: r.bold = True
        if italic: r.italic = True
        if size: r.font.size = Pt(size)

def H1(t): doc.add_heading(t, level=1)
def H2(t): doc.add_heading(t, level=2)
def bullets(items, style='List Bullet'):
    for it in items:
        p = doc.add_paragraph(style=style); add_runs(p, it); p.paragraph_format.space_after = Pt(3)

def set_cell_bg(cell, color):
    tcPr = cell._tc.get_or_add_tcPr(); shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear'); shd.set(qn('w:color'), 'auto'); shd.set(qn('w:fill'), color); tcPr.append(shd)

def table(rows, widths, header=True, size=9.5, caption=None):
    t = doc.add_table(rows=len(rows), cols=len(rows[0])); t.style = 'Table Grid'; t.alignment = WD_TABLE_ALIGNMENT.CENTER; t.autofit = False
    for j, w in enumerate(widths): t.columns[j].width = Inches(w)
    for i, row in enumerate(rows):
        for j, val in enumerate(row):
            c = t.cell(i, j); c.width = Inches(widths[j]); c.text = ''
            p = c.paragraphs[0]; p.paragraph_format.space_after = Pt(1)
            add_runs(p, str(val), bold=(header and i == 0), size=size)
            if header and i == 0: set_cell_bg(c, 'E7E6E6')
    if caption:
        p = para(caption, size=9.5); p.paragraph_format.space_before = Pt(3)
    return t


# page numbers
_fp = sec.footer.paragraphs[0]; _fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
_r = _fp.add_run()
for _t, _txt in (('begin', None), (None, 'PAGE'), ('end', None)):
    if _t:
        _e = OxmlElement('w:fldChar'); _e.set(qn('w:fldCharType'), _t)
    else:
        _e = OxmlElement('w:instrText'); _e.set(qn('xml:space'), 'preserve'); _e.text = _txt
    _r._r.append(_e)

import sys, collections, statistics as _st, json
import final_data as FD
from final_data import wilson
WIPERS = ['chunk256','daemonized_per_file','enc_delete','exfil_delete','forked_per_file','header_footer','hex_lowentropy','inplace_full','intermittent','paced_1.4s','rename_only','sig_preserving','tmp_rename_over','trunc_rewrite']
RWS = ['rw_chunk4k','rw_inplace','rw_paced_1.4s','rw_tmp_rename','rw_trunc']
ATTACKS_ALL = WIPERS + RWS
LABEL = {'chunk256':'Wiper, in place, 256 B chunks','daemonized_per_file':'Wiper, one double-forked process per file','enc_delete':'Write .enc copy, delete original','exfil_delete':'Copy out, delete original','forked_per_file':'Wiper, one child process per file','header_footer':'Overwrite header and footer only','hex_lowentropy':'Encode as hex (entropy-capped)','inplace_full':'Wiper, in place, whole file','intermittent':'Wiper, every other block','paced_1.4s':'Wiper, 1.4 s per file','rename_only':'Rename with new extension, no content change','sig_preserving':'Random bytes behind the original signature','tmp_rename_over':'Write temp file, rename over original','trunc_rewrite':'Truncate, then rewrite with random bytes','rw_chunk4k':'Read-encrypt-write, in place, 4 KiB chunks','rw_inplace':'Read-encrypt-write, in place','rw_paced_1.4s':'Read-encrypt-write, 1.4 s per file','rw_tmp_rename':'Read-encrypt, temp file, rename over','rw_trunc':'Read-encrypt, truncate, write back'}
assert set(ATTACKS_ALL) == set(FD.ATTACKS), set(FD.ATTACKS) ^ set(ATTACKS_ALL)
NPRE = 4
TOTAL_ATT = sum(len(v) for v in FD.ATT.values())
FPT = {c: FD.fp_total(c) for c in FD.CFGS}
NWL = FPT['holdfast']['workloads']
def pct(x, d=0): return f'{x*100:.{d}f}%'
def wil(k, n): lo, hi = wilson(k, n); return f'{lo*100:.1f}% to {hi*100:.1f}%'
def hi(k, n): return f'{wilson(k, n)[1]*100:.1f}%'

def acell(cfg, cor, a):
    c = FD.cell(cfg, cor, a); n = c['n']
    if c['det'] > 0:
        t = f"{c['det']}/{n} · {c['live']*100:.0f}%"
    else:
        t = f"0/{n} · store {c['dur']*100:.0f}%"
    if c['det'] < n and c['alerts'] > 0: t += ' ‡'
    return t

def attack_rows(cor, cfgs):
    rows = [['Attack (6 trials each)'] + ['restore-only', 'redirect-only', 'Holdfast', 'Holdfast strict']]
    for grp, names in (('Wipers (never read the target)', WIPERS), ('Read-encrypt-write', RWS)):
        rows.append([f'**{grp}**', '', '', '', ''])
        for a in names: rows.append([LABEL[a]] + [acell(c, cor, a) for c in cfgs])
    return rows

def alert_stats(cfg, cor=None):
    und = al = rec = noal = 0; noal_lost = 0
    for (c, co, a), rs in FD.ATT.items():
        if c != cfg or (cor and co != cor): continue
        for r in rs:
            if int(r['detected']): continue
            und += 1
            if r['alert_rollback_intact'] != '':
                al += 1; rec += int(r['alert_rollback_intact']) == int(r['nfiles'])
            else: noal += 1
    return dict(und=und, al=al, rec=rec, noal=noal)
def fullfrozen(cfg, cor):
    return [a for a in ATTACKS_ALL if FD.cell(cfg, cor, a)['det'] == 6 and FD.cell(cfg, cor, a)['full'] == 6]
def ada(cfg, cor):
    rs = [r for r in FD.ADA if r['cfg'] == cfg and r['corpus'] == cor]; n = len(rs)
    L = [int(r['lost']) / int(r['n']) for r in rs]; L2 = [int(r['lost_after_recovery']) / int(r['n']) for r in rs]
    return dict(n=n, det=sum(int(r['detected']) > 0 for r in rs), cl=sum(int(r['cluster']) > 0 for r in rs), m=sum(L)/n, m2=sum(L2)/n,
                zero=sum(l == 0 for l in L), zero2=sum(l == 0 for l in L2), big2=sum(l > 0.25 for l in L2), rows=rs, L2=L2)

hf_m = len(fullfrozen('holdfast', 'mixed')); st_u = len(fullfrozen('prov', 'unknown')); hf_u = len(fullfrozen('holdfast', 'unknown'))
A_h = alert_stats('holdfast'); A_hm = alert_stats('holdfast', 'mixed'); A_hu = alert_stats('holdfast', 'unknown')
rs_m = [FD.cell('restore_only', 'mixed', a)['live'] for a in ATTACKS_ALL if FD.cell('restore_only', 'mixed', a)['det']]
fp_h = FPT['holdfast']; fp_r = FPT['restore_only']; fp_d = FPT['redirect_only']; fp_s = FPT['prov']
adm = ada('holdfast', 'mixed'); adu = ada('holdfast', 'unknown'); arm = ada('restore_only', 'mixed'); aru = ada('redirect_only', 'unknown')
S5P = sorted({w for (w, c), v in FD.S5.items() if c == 'prov' and any(int(x['detections'] or 0) > 0 or x['error'] for x in v)})
S5H = sorted({w for (w, c), v in FD.S5.items() if c == 'holdfast' and any(int(x['detections'] or 0) > 0 or x['error'] for x in v)})
S5W = sorted({w for (w, c) in FD.S5})
rwu_h = [FD.cell('holdfast', 'unknown', a)['det'] for a in RWS]; rwu_p = [FD.cell('prov', 'unknown', a)['det'] for a in RWS]

para('Holdfast: A Ransomware-Resistant Linux Filesystem with Read-Provenance Detection and Recovery that Does Not Depend on Detection', bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, size=16)
para('Sivaseelan Sa', align=WD_ALIGN_PARAGRAPH.CENTER)
para('Department of Computer Science and Engineering (Core), Vellore Institute of Technology (VIT), Vellore, India. sivaseelan.s@outlook.com', align=WD_ALIGN_PARAGRAPH.CENTER)
para('All numbers come from one frozen build and the harness published with the code (Sec. 9). Code and data: ' + CODE_URL + '.', italic=True, align=WD_ALIGN_PARAGRAPH.CENTER, size=9.5)

H1('Abstract')
para(f'A ransomware-resistant filesystem has two jobs: notice destructive writes quickly, and keep the originals recoverable when it does not. Both jobs are hard on data that already looks like noise (compressed media, encrypted archives): overwriting noise with ciphertext shows no entropy rise and no destroyed file signature, so content-based detectors cannot separate encryption from a benign re-sync. We present **Holdfast**, a C++17 FUSE3 filesystem for Linux with two main ideas. (1) **Read provenance**: the daemon remembers which files a process read through the mount, and an in-place overwrite of a high-entropy original by unrelated high-entropy bytes counts as destroyed content when the writer read that file first. On unknown-format data this raised detection of read-encrypt-write attackers from {sum(rwu_h)} of {6*len(RWS)} to {sum(rwu_p)} of {6*len(RWS)} trials, with each attacker frozen after two to four files and every original intact, and with no false positive on {NWL} benign workloads in four suites; its price is that {len(S5P)} of {len(S5W)} deliberately adversarial look-alikes (a program that hashes or compares a file and then overwrites it with new noise-like data, or re-encrypts a vault) are frozen too, so the signal is opt-in, and it does not cover wipers that never read their targets. (2) **Recovery that does not depend on detection**: a copy-on-write ring keeps the original bytes of every overwritten, truncated, renamed or deleted file, held writes are shelved rather than discarded so false positives are releasable, and an operator can rebuild a checkpoint from the ring and roll back. In 96 attack trials, 60 of which were never frozen and 42 of which raised no alert at all, `promote recover` followed by `rollback` restored every original, even after 12 rewrites of each file. Around these we built a testbed that implements the two published decision principles, restore-after-detect (ShieldFS [5]) and hold-before-commit (Redemption [6]), and a hybrid of them in one codebase, with a randomized attacker generator, a {NWL}-workload benign suite built from real tools and a loss analysis. In {TOTAL_ATT} randomized attack trials ({len(WIPERS)} wiper styles and {len(RWS)} read-encrypt-write styles, two corpora, four configurations; the baselines are our re-implementations of each system\'s decision principle, not the original systems) the default hybrid froze {hf_m} of {len(ATTACKS_ALL)} attack styles in every trial with every original intact in the live view on recognizable formats, while restore-only leaves 59% to 94% and redirect-only 59% to 87% of the files intact at the freeze on the attacks they catch; the default build froze none of the {fp_h["workloads"]} benign workloads ({fp_h["trials"]} trials; 95% upper bound {hi(0, fp_h["trials"])} per trial) against {fp_r["frozen"]} and {fp_d["frozen"]} for the two baseline principles. We also report what no configuration freezes, and a measured cost: hold-back is slow on our VM. All attackers are synthetic and run on one virtual machine; no real malware was used, and recovery actions are scripted, so real recovery needs an operator who acts on an alert or on suspicion.')
para('**Keywords:** ransomware, filesystem, FUSE, write redirection, copy-on-write, anomaly detection, recovery, false positives', size=10)

H1('1  Introduction')
para('Ransomware must eventually mutate files, so the filesystem is a natural place to observe and contain it. Detection signals such as entropy and file-type change [1], [2] and learned behavior models [3], [4] are well studied. What happens to the victim\'s files between the first malicious write and the moment of detection is decided by the recovery paradigm. ShieldFS [5] shadows a file when a process first opens it for write or delete and restores from the shadow store after detection, so the user-visible file is damaged until restoration. Redemption [6] redirects every write to a protected area and commits it only after a verdict, so detection delay costs no data for the writes it covers. Each paradigm has been published with its own detector, platform (Windows), attacker set and metrics, which makes it hard to say which design choice buys what.')
para(f'Holdfast is a Linux/FUSE testbed built to make that comparison controlled, with reliability (few false positives, recoverable false positives) as the top design goal. It implements three decision paradigms as configuration presets over one code base (Sec. 3.3), a randomized attacker generator with {len(ATTACKS_ALL)} styles, and a benign suite of {NWL} workloads run with real tools. **We do not claim write redirection or restore-after-detect as contributions**; they come from [6] and [5]. The new parts are the read-provenance signal and the detection-independent recovery path; the rest is the testbed that evaluates them. The contributions are:')
bullets([
 '**Read provenance for the noise-over-noise blind spot** (Sec. 3.8, 3.14, 5.3, 5.5): an opt-in signal that separates read-transform-write from copy-over, evaluated with read-encrypt-write attackers, an adversarial look-alike suite and four benign suites, with its false-positive cost and evasions stated.',
 '**Recovery that does not depend on detection** (Sec. 3.7, 3.13, 5.4): an original-byte ring, shelved held writes with an operator release, alert checkpoints, and a recover command that rebuilds a checkpoint from the ring; all 96 trials were restored, including 60 that were never frozen and 42 that raised no alert.',
 '**A controlled comparison** of restore-only, redirect-only and a hybrid in one implementation, under 912 randomized attack trials and 1,320 benign trials on four suites, with confidence intervals (Sec. 5).',
 '**A hybrid design** in which hold-back covers overwrite and truncation while an undo journal with quarantine covers replace, delete and rename; neither mechanism alone protects the live view against both classes (Sec. 3.4, 3.7, 5.2).',
 '**A reliability-first response model** (Sec. 3.10, 3.11): soft and hard detection tiers, a cooperation-aware hold tier, and a false-positive evaluation on four suites plus an adversarial fifth (Sec. 5.5).',
 '**Rate-independent and process-tree signals** with an analytic damage-rate bound for attackers whose writes carry content evidence (Sec. 3.6, 3.9, 5.7).',
 '**Negative results**: attack classes no configuration freezes, an opt-in faster copy path that did not help on our filesystem, and a measured cost of hold-back (Sec. 5.2, 5.8).',
 '**A documented implementation and harness**: C++17 source, eleven CTest suites, and the attacker and benign suites behind the numbers. The code, harness and result data are released under the MIT license (Sec. 9).',
])
para('We use synthetic attackers on one small VM and re-implement baselines rather than run the original systems; Sec. 5.1 and Sec. 6 list the consequences.')

H1('2  Background and Related Work')
H2('2.1  Detection signals and learned detectors')
para('CryptoLock [1] flags encryption-like change using file-type change, similarity and entropy indicators. UNVEIL [2] builds a simulated user workspace in a sandbox and flags programs that manipulate it like ransomware. Sgandurra et al. [3] apply dynamic analysis and supervised learning and Homayoun et al. [4] mine frequent behavior patterns. Holdfast does not learn from data: it uses a hand-set additive score so that every decision can be traced in the audit log.')
H2('2.2  Recovery paradigms')
para('**Restore-after-detect.** ShieldFS [5], a Windows minifilter-based system, copies a file into a read-only shadow store the first time a process opens it for write or delete, scores processes with random forests over I/O features at several time scales, and restores after detection; it reports 298 of 305 unseen samples detected and all 97,256 compromised files recovered, with an estimated 0.26x user-perceived overhead. **Hold-before-commit.** Redemption [6] (Windows) redirects each write request to user files to a protected area, kept as a sparse "reflected file", and commits the changed blocks to the original after the process is judged benign (or after user confirmation), discarding them otherwise. Its detector scores entropy change between reads and writes, the number of blocks overwritten, deletions, directory traversal, writes across document types and the interval between writes to different files. It reports 100% true positives at 0.8% false positives on 677 test samples from 29 families with a median of 5 files attacked, and 2.6% mean application runtime overhead, and it acknowledges that a stealthy attacker encrypting one file every six hours is not bounded. **Hardware-level retention.** FlashGuard [11] retains invalid flash pages so encrypted data can be restored from the SSD. **Immutability.** VaultFS [12] enforces write-once semantics for cold data in a Linux kernel module and does not detect anything.')
H2('2.3  Linux and cost-focused work')
para('GuardFS [7] is a Linux overlay filesystem with ML-driven defenses that obfuscate, delay or track file access. RWGuard [8] is a real-time detector with file protection. van Sloun et al. [9] report that even simple features such as buffer entropy can raise execution time by up to 350% and reduce SSD performance by up to 75%, and propose monitoring more features only for suspicious processes. SHIELD [10] moves filesystem features off-host for ML detection.')
H2('2.4  Evasion, cooperation and detectability')
para('Splitting ransomware across cooperating benign-looking processes drove a per-process detector from 98.6% to 0% detection in The Naked Sun [14]; intermittent encryption of parts of files has a quantified detectability limit and chunk-level models outperform whole-file analysis [15]; hand-built low-level behavioral variants cut a classifier\'s recall from 0.98 to 0.64 [16]; and eBPF-based in-kernel detection moves the observation point but not the decision problem [17]. Holdfast\'s parent-bucket aggregation, cluster hold tier and the adaptive search of Sec. 5.6 respond to the first two; none of these papers measure false positives in the way Sec. 5.5 does, and we have not reproduced their attacks. The closest work on graded, risk-based response that we found is Begovic et al. [18], who combine ML on kernel function traces with SELinux booleans that deny write and append for a process once encryption looks likely; they report false-positive rates of roughly 1% to 2% for their model and 0.5% to 1% for their rules on non-encryption workloads, and note that some bytes (about 10 to 20 KB at the median) are written before the first block. Their mechanism denies writes and has no hold-back, shelving or rollback, and their workloads differ from ours, so the numbers are not comparable; we mention them as context for what false-positive rates a Linux defense can reach.')
H2('2.5  Positioning')
table([
 ['Aspect','Prior art','Holdfast'],
 ['Write redirection with verdict-based commit','Redemption [6] (Windows, entropy-change features)','Same principle on Linux/FUSE; commit is gated on the owner\'s score staying below half the threshold and a quiet delay (not novel in principle)'],
 ['Shadow copy + restore after detection','ShieldFS [5]','Same principle (copy-on-write ring); used as a baseline preset'],
 ['Evaluation basis','Each system with its own detector and platform','All paradigms in one code base, same attackers, same benign suite'],
 ['Namespace attacks (replace, delete, rename)','Handled by shadow restore [5]; coverage by redirection not detailed in [6]','Undo journal + quarantine on top of hold-back; ablation shows both are needed'],
 ['Slow / split attackers','[6] concedes one file per six hours is unbounded','Cumulative slow-burn and parent aggregation; a damage-rate bound, not a guarantee'],
 ['Real malware','Hundreds of real samples [5], [6]','None (synthetic attackers only)'],
], [1.6,2.2,2.7], caption='**Table 1.** Positioning (descriptions of [5], [6] from their published text).')

H1('3  Design')
H2('3.1  Threat model')
para('The adversary is a user-level process or small process tree under an unprivileged account other than the daemon\'s that destroys files in the protected directory by overwriting, truncating, replacing, renaming or deleting them, at any pace, in pieces, or from child processes. We assume the daemon, its backing store and the kernel are not compromised. We do **not** defend against root, a process under the daemon\'s uid, direct access to the backing directory, or attackers whose processes have no common parent that is not init (Sec. 6).')
H2('3.2  Architecture')
para('Holdfast is a stackable FUSE3 filesystem over a backing directory (Figure 1; the binaries keep the working name `rrfs_fuse` and `rrfs_ctl`). Each mutating operation passes a blocked-key gate (a flagged PID or parent receives EACCES), a copy-on-write step that preserves the bytes about to change, the anomaly engine, and the hold-back overlay. A threshold crossing suspends the offender (SIGSTOP), discards its held writes and runs the scoped repair. Operators use pseudo-files `.rrfs_control` and `.rrfs_status` through `rrfs_ctl`; writes to `.rrfs_state/` through the mount return EACCES.')
doc.add_picture(os.path.join(HERE, 'rrfs_architecture_diagram.png'), width=Inches(6.4))
doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
para('**Figure 1.** Holdfast architecture. (1) copy-on-write ring, (2) multi-signal engine, (3) response, (4) hold-back overlay, (5) undo journal and scoped repair.', size=9.5, align=WD_ALIGN_PARAGRAPH.CENTER)
H2('3.3  Three decision paradigms as presets')
table([
 ['Preset','Hold-back','Content delta','Slow-burn','Parent aggregation','Scoped repair','Ambiguity policy'],
 ['restore-only (ShieldFS principle)','off','off','off','off','off','off'],
 ['redirect-only (Redemption principle)','on','entropy-jump only (type weight 0)','off','off','off','off'],
 ['Holdfast (hybrid)','on','on','on','on','on','defer (default) or freeze'],
], [1.7,0.7,1.2,0.7,0.8,0.7,0.8], size=8.5, caption='**Table 2.** Presets. "Holdfast strict" is the Holdfast row with `read_provenance = true` (Sec. 3.14); it is the same binary. The first two re-implement each system\'s decision **principle** inside our code; they are not the original systems, which differ in detector (random forests, weighted feature average), platform and storage format.')
para('One deviation matters for reading the results: in the redirect-only preset the content-delta check still marks a write whose file type or text nature was destroyed as a corroborating event for the burst term, with zero score weight of its own.')
H2('3.4  Hold-back overlay')
para('A write is **destructive** if it overwrites existing bytes (offset below the file\'s current size), follows a truncation of existing data by the same process, or deletes an existing file; a file created by the same process is never destructive. The first destructive write to a file creates a pending copy under `.rrfs_state/pending/`; later writes go to it, and reads, `stat` and `readdir` are served from it so the owner sees its own changes while the backing store keeps the original. A held file is **committed** by atomic rename when its owner has been quiet for `holdback_commit_delay_ms` (default 2000) and the owner\'s score is below `holdback_commit_score_frac` x threshold (0.5), or on fsync; it is **discarded** if the owner is flagged. Holding is whole-file; files over 64 MB are written in place with copy-on-write only; beyond 256 held files the oldest are force-committed; pending files left by a crash are discarded at startup.')
H2('3.5  Scoring signals')
para('Each key (PID and parent bucket) has a decaying additive score (decay 0.5/s, threshold 10). Contributions: bias-corrected entropy above 7.5 bits/byte of a destructive write, a burst term for six corroborated distinct paths within 5 s, extension churn on renames (weight 3), and **content delta**: the preserved original bytes are compared with the new bytes for a destroyed file signature, text turned to binary (weight 3 each) or an entropy rise of at least 1 bit/byte (needs at least 128 compared bytes). Only bytes that clobber existing data are scored; writes into new files are remembered, scored only if the process later renames them over an existing file or deletes an existing file, and are exempt when they carry a known signature (so extracting a JPEG archive is silent). A rename of a file created by the same process to a name that drops its suffix (`.tmp`, `.lock`, ...) is not extension churn.')
H2('3.6  Slow-burn and process-tree aggregation')
para('The **slow-burn** signal counts distinct files with a corroborated destructive event in a sliding 300 s window without decay and forces a detection at 8 files, so pacing cannot hide a content-evident attack. Every event is also scored against the writer\'s parent bucket (parents other than init), so a shell loop that spawns one process per file accumulates in the parent; both PID and parent are then blocked and stopped.')
H2('3.7  Scoped repair and quarantine')
para('Mutations are journaled per key. On detection the offender\'s held writes are discarded and, for its other paths, the oldest copy-on-write generation restores the file; files the offender created, and rename destinations that did not pre-exist, are moved to `.rrfs_state/quarantine/`, never deleted. An auto-checkpoint of the pre-attack tree can also be rebuilt from the ring and applied with two atomic rename(2) calls.')
H2('3.8  Ambiguous overwrites')
para('A destructive write that replaces high-entropy bytes with high-entropy bytes and shows no content evidence is **ambiguous**: it is what encryption of already-compressed or unknown-format data looks like, and also what a benign re-sync of media over an older copy looks like. After `ambiguous_files` (8) distinct ambiguous files from one key, policy **off** ignores them, **defer** (default) withholds commit of the key\'s held writes for `ambiguous_defer_ms` (30 s) after the last one, logs an `ambiguous` event and lets the operator run `rrfs_ctl <mount> discard <pid>`, and **freeze** treats the burst as a detection.')
H2('3.9  A damage-rate bound')
para('Let s be a key\'s score, lambda the decay and theta the threshold. Suppose each file the attacker touches yields a corroborating event (a destroyed signature, text turned to binary, an entropy rise, a rename with new extension, or a deleted file after fresh high-entropy writes). **Claim.** Within any window of W = 300 s a single key can touch at most N_s - 1 = 7 distinct files without a detection, at any rate, so the attacker\'s sustained damage rate is at most (N_s - 1)/W = 1.4 files per minute per key; with k independent keys (no common non-init parent) it is at most k times that. Argument. Distinct corroborated files are recorded with timestamps and expire after W; at N_s entries the engine adds theta to the score. Fast attackers are caught earlier by the decaying score (a steady rate r adds about w r / lambda). The bound is **not** a total-loss bound: a patient attacker below the rate is never flagged, and it does not apply to files whose overwrite carries no content evidence (Sec. 3.8). Scoped repair restores touched files from the ring (8 generations by default) if detection occurs before the ring wraps. Sec. 5.7 tests the boundary empirically.')

H2('3.10  Graded response, shelving and release')
para('A threshold crossing is classified by its evidence. A **hard** detection requires content evidence (a high-entropy overwrite, a destroyed signature or a text-to-binary change) on at least `hard_min_content_files` (default 2) distinct files in the slow window; it blocks the key, stops the offender and its parent (SIGSTOP) and repairs as before. A crossing driven only by renames and extension changes is a **soft** detection: it is logged (event `detect_soft`) at most once per minute per key and nobody is stopped or blocked, because renames alone destroy no bytes and are the dominant source of benign look-alikes (version suffixes, case changes, mail flags, rotation chains). On a hard detection the offender\'s held writes are **shelved** instead of discarded: they are hidden from readers (who see the original) and never auto-committed, but kept, so that `rrfs_ctl <mount> release <pid>` can commit them, un-block the key and resume both the offender and the parent we stopped. Release commits the held writes and puts back the paths that the repair moved (Sec. 3.13); in-place writes that bypassed hold-back (files over 64 MB) are not recoverable this way. Three narrower rules close specific false positives found in S2: a conversion between two known formats (JPEG to PNG) is not "type destroyed" (if the new bytes are also noise the ambiguity policy applies); deleting a file the same process created is not destructive; and a delete never counts as content evidence by itself.')
H2('3.11  Cooperation-aware and cumulative hold tier')
para('Content-evidence events (from in-place writes, rename-over of a file that was filled with noise, and deletes after such a file) are also accumulated per **cluster**: the writer\'s executable, and a global cluster. When an executable cluster reaches 8 distinct evidence files from at least 3 distinct processes inside the slow window, or the global cluster reaches 16 files, the commits of every member\'s held writes are withheld until 30 s after the last evidence, a checkpoint is taken, and an alert tells the operator to review or run `rrfs_ctl <mount> discard cluster`. The tier is hold-only by design: it never freezes anyone, so its false-positive cost is a delayed commit. Its limit is equally by design: it only protects writes that were held, so replace-style attackers (rename-over, copy-and-delete) that split across processes are alerted and checkpointed but not stopped (Sec. 5.6). A separate alert-only rule logs a soft detection when one process deletes 16 or more pre-existing files.')
H2('3.12  What can and cannot be bounded')
para('Three statements, each with its assumptions. (1) **Held writes.** For a process that is detected, every in-place overwrite or truncation of a file up to 64 MB that it made before detection is in a pending copy, so the original bytes are intact in the backing store; this holds irrespective of pace, but not beyond 256 held files (older ones are force-committed) and not for larger files. (2) **Rate bound.** For attackers whose writes carry content evidence, one key can touch at most N_s - 1 = 7 distinct files per 300 s window before the slow-burn signal forces a detection (Sec. 3.9); a hard detection additionally needs content evidence on two files, which delays detection by at most one file. Attackers using q independent keys (no common non-init parent, no shared executable) get q times this budget. (3) **False positives.** With zero false positives in n independent trials the one-sided 95% upper bound on the rate is about 3/n (Wilson: 1.2% for n = 330), and the n workloads here are not an i.i.d. sample of real use, so the number bounds our suites, not a deployment. No claim of zero false positives is made or possible: any rule that freezes a process for destroying content can freeze a legitimate tool that does the same, and the shelving and release path exists for that case.')

H2('3.13  Persistence, release undo and alert checkpoints')
para('Four changes make the reliability path usable by an operator. (1) **Shelf manifest.** When a flagged process\'s held writes are shelved, their pending copies and owners are recorded in a small manifest next to them; after a daemon crash or restart the shelved copies are recovered (still hidden from readers) and can be released or discarded by the old process id. Unshelved pending copies are still dropped, so the backing store keeps the previous version. (2) **Release undoes the repair.** The detection-time repair moves every file the offender created or replaced into a quarantine directory before restoring originals; a release now moves those files back and keeps what the repair had restored in an undo directory (nothing is deleted). (3) **Alert checkpoints.** A soft alert (rename or extension activity with no content evidence) and the first noise-over-noise ambiguity event each take a checkpoint rebuilt from the original-byte ring, and a soft alert also withholds the process\'s held commits for 30 s. Neither stops anyone. (4) **Recovery checkpoint.** The operator command promote recover builds a checkpoint from the ring at the time of the command, so a rollback after a long, undetected attack restores the original bytes rather than a tree that is already damaged.')

H2('3.14  Read provenance (opt-in strict mode)')
para('The noise-over-noise blind spot (Sec. 3.8) exists because the content tests compare bytes, and two buffers of random-looking bytes look alike whether one is a ciphertext of the other or both are unrelated. What differs is how the writer came to hold the new bytes. Ransomware must read the victim file, transform it and write the result back. A plain copy-over of a new version never reads its destination. The daemon therefore remembers, per process and per parent, which paths were read through the mount in the last two minutes (the parent is recorded so that a pipeline such as a reader feeding an encryptor is linked). When an in-place write replaces high-entropy original bytes with high-entropy new bytes, with no ordinary content evidence, and the writing process (or its parent) read that file, the write is scored as destroyed content, so the normal hard-detection rules apply. Two refinements came from our own false-positive runs. (1) The new bytes must differ from the old in at least 35% of bits: a small edit of a noise-like file (flipping a byte of a JPEG, rewriting container pages by a bit-flip) is a modification, not a transform, whereas random against random differs in about half of the bits. (2) A process that writes a recognisable file signature at offset 0 of a file is producing a valid file of a known format (an image recompressor), and its later chunks of that file are exempt. Both are weaknesses an attacker could use, and the second is stated as such in Sec. 5.3 and 5.5. The mode is off by default (read_provenance = false).')


H1('4  Implementation')
para('Holdfast is about 3,400 lines of C++17 (plus about 1,000 lines of unit tests) on libfuse 3.14 and CMake. Decision logic (anomaly engine, canary manager, hold-back, content delta, extension tracker, entropy) is in plain classes without a FUSE dependency and is covered by eleven CTest suites. Unit and live attack runs were also done under AddressSanitizer/UBSan with no reports; ThreadSanitizer was run only on a standalone stress of the hold-back and engine. The evaluation harness (Python) mounts a fresh instance per trial, seeds a randomized corpus, runs the attacker as a disposable subprocess, and records detection, live-view and durable-state integrity, time to detection and files touched from the audit log. The repository layout and build instructions are in its README (Sec. 9).')


H1('5  Evaluation')
H2('5.1  Methodology and threats to validity')
para(f'Experiments ran on one sandbox VM (2 vCPU, Linux 6.18, libfuse 3.14, daemon as root) with the configuration of Appendix A unless stated, and with periodic baseline checkpoints disabled so that the comparison isolates the paradigms. **Presets** (Table 2): restore-only, redirect-only, Holdfast (default) and Holdfast strict, which is the same binary with `read_provenance = true`. **Attack matrix:** {len(WIPERS)} wiper styles and {len(RWS)} read-encrypt-write styles ({len(ATTACKS_ALL)} in all) on corpora of 16 to 32 files of 4 to 48 KB with randomized seeds, sizes and counts; the "mixed" corpus has text, JPEG-signature and ZIP-signature files in thirds, the "unknown" corpus is pure random bytes. Each cell has 6 trials per preset, {TOTAL_ATT} trials in all. A wiper overwrites a file with random bytes without reading it; a read-encrypt-write attacker reads the file, XORs it with a SHA-256 counter-mode keystream and writes the result back (in place, truncating first, in 4 KiB chunks, through a temporary file renamed over the original, or paced at 1.4 s per file). For each trial we record whether the attacker was frozen (a hard detection), the share of the originals that are byte-identical **in the live view at the freeze** with no operator action, the share intact in the backing store ("store") when the attacker has finished and the daemon has settled, and, when no hard detection occurred but an alert was raised, whether rolling back to the alert checkpoint restored every original. **Benign suites:** {NWL} workloads in four suites (S1 to S4: 24, 37, 25 and 24 workloads) run through the mount with real tools (cp, tar, zip, rsync, sed -i, git, gcc and make, sqlite, gzip, openssl, logrotate-style renames, PIL and ImageMagick re-encoding, iconv, dd and others), 3 repetitions per preset and workload ({FPT["holdfast"]["trials"]} trials per preset), with the result checked for correctness. A fifth suite (S5, {len(S5W)} workloads, 3 repetitions) is deliberately adversarial to the read-provenance signal. A workload counts as **frozen** if any repetition raised a hard detection or timed out because the workload was blocked. **Adaptive search:** 40 randomized attackers per corpus (Sec. 5.6). **Caveats, to read before any number:** (a) attackers and workloads were written by the author, and the two baselines are our re-implementations of the decision principle of each published system, so the ranking among presets is about principles, not about ShieldFS or Redemption themselves; (b) the thresholds and rules were developed while running S1 and S2, and S2 was used to fix false-positive rules; S3 was written before those fixes and run once afterwards; S4 was written before the later changes (including the strict mode) were evaluated; all suites were written by the same author, and two refinements of the strict mode (Sec. 3.14) and three narrow rules of the graded response (Sec. 3.10) were added after seeing false positives on these same suites, so no suite is an untouched hold-out for every rule; one S4 workload (rsync) originally skipped files by its modification-time quick check and was changed to `--checksum`, a fix to the test and not to the daemon; (c) 6 trials per cell give Wilson intervals of roughly [61, 100]% for 6/6 and [0, 39]% for 0/6; (d) one VM, synthetic attackers, no real malware, no comparison with the original systems, and no second machine to test repeatability across hardware.')

H2('5.2  Attack matrix on recognizable formats')
rows = attack_rows('mixed', ['restore_only', 'redirect_only', 'holdfast', 'prov'])
table(rows, [2.3, 1.05, 1.05, 1.05, 1.05], size=8, caption=f'**Table 3.** Mixed corpus (text, JPEG, ZIP). Cell: attackers frozen / trials, then the mean share of the originals intact in the live view at the freeze. Where the attacker was never frozen the cell gives the share intact in the backing store after settling ("store"). ‡ = an alert was raised in at least one such trial (Table 5).')
assert sorted(a for a in ATTACKS_ALL if FD.cell('holdfast','mixed',a)['det']<6)==['daemonized_per_file','exfil_delete','rename_only']
para(f'On recognizable formats the default Holdfast froze {hf_m} of the {len(ATTACKS_ALL)} attack styles in all 6 trials, each with 100% of the originals intact in the live view at the freeze. The three it did not freeze are the rename-only attack, copy-out-and-delete and the double-forked per-file wiper. The first (rename with a new extension and no content change) is deliberately only a soft alert, because renames alone destroy no bytes and are the main source of benign look-alikes (Sec. 3.10); the second and third leave no content evidence in the process the daemon watches (the data is copied out, or each file is handled by a process whose parent has exited). For all three the daemon raised an alert and took a checkpoint in every trial. Restore-only froze most of the other attacks but, by construction, only after the destructive writes landed: the originals intact in the live view at the freeze ranged from 59% to 94%, and the files are recovered by the restore afterwards rather than protected. Redirect-only matches Holdfast on overwrites and truncations (100% intact) but not on attacks that replace, delete or rename files (59% to 87% intact, for example 64% for write-encrypted-copy-then-delete and 59% for read-encrypt-through-a-temporary-file), because held writes only cover bytes that were overwritten in place. Neither baseline froze the paced attacker at 1.4 s per file, the per-child-process wiper that Holdfast catches by parent aggregation, or the double-forked per-file process. Redirect-only froze 5 of 6 trials of the signature-preserving wiper, with 83% intact. After the paced attackers ran to completion, redirect-only retained 34% of the originals in the backing store and restore-only none.')

H2('5.3  Unknown-format data and read provenance')
rows = attack_rows('unknown', ['restore_only', 'redirect_only', 'holdfast', 'prov'])
table(rows, [2.3, 1.05, 1.05, 1.05, 1.05], size=8, caption='**Table 4.** Unknown corpus (random bytes only, so no signature or text to destroy). Same cell format as Table 3. ‡ = alert raised in at least one trial.')
cu = lambda c, a: FD.cell(c, 'unknown', a)
inp = ['chunk256', 'inplace_full', 'intermittent', 'rw_chunk4k', 'rw_inplace', 'rw_trunc', 'trunc_rewrite', 'header_footer', 'sig_preserving']
para(f'With no signature or text to destroy and an entropy already near 8 bits/byte, a noise-over-noise overwrite looks like a benign re-sync of media over an older copy, so the content tests have no evidence to offer. The three presets answer differently. **Redirect-only** (entropy jump only) detects none of the in-place, truncating or chunked attacks on this corpus, and loses the files. **Restore-only** scores the high entropy of the new bytes alone and therefore freezes these attacks, which is also why it has the highest false-positive count on the benign suites (Sec. 5.5). **Holdfast**, whose default ambiguity policy is "defer", does not freeze them: in all 6 trials of each of the {len(inp)} in-place or truncating attack styles above it raised an ambiguity alert, withheld the commit of the held writes and took a checkpoint, so the originals were still intact in the backing store (store 100%) when the attacker finished, and rolling back to the checkpoint restored them in all of those trials (over the whole corpus, {A_hu["rec"]} of the {A_hu["al"]} alerted, undetected trials). It froze only the attacks that rename over or delete the original after writing noise ({", ".join(LABEL[a].lower() for a in ("enc_delete", "tmp_rename_over", "rw_tmp_rename"))}). The deferral is a decision to protect the data without stopping anyone: the live view shows the attacker\'s writes, and the held writes are committed 30 s after the last ambiguous event unless the operator acts (`discard`). Three wipers raise no alert at all on this corpus (hex encoding, one double-forked process per file and one child process per file), and in those trials the data is lost unless the operator recovers from the ring without being prompted (Table 6): {A_hu["noal"]} of {A_hu["und"]} undetected trials produced no alert. Paced attackers (1.4 s per file) were still partly committed by the time the trial was measured (store about {FD.cell("holdfast", "unknown", "paced_1.4s")["dur"]*100:.0f}%).')
para(f'**Read provenance.** In strict mode the {len(RWS)} read-encrypt-write styles were frozen in {sum(rwu_p)} of {6*len(RWS)} trials on the unknown corpus ({sum(rwu_h)} of {6*len(RWS)} for the default build), after a median of {int(_st.median([FD.cell("prov", "unknown", a)["ft"] for a in RWS]))} files touched, with every original intact in the live view. The wipers that never read their targets are, as expected, not covered: strict mode still defers and alerts on them, exactly as the default build does, and the double-forked, forked and hex-encoding wipers remain undetected. The signal is a statement about what the writer did before it wrote, not about the bytes: it needs reads to go through the mount and is evaded by an attacker that reads the file in advance by other means (for example a separate helper process reading through a path outside the mount, or reading from a copy), by one that first writes a valid file header, and it misclassifies the look-alikes of Sec. 5.5.')

H2('5.4  Recovery after an alert, and without one')
tab = []
for cfg, lab in (('restore_only', 'restore-only'), ('redirect_only', 'redirect-only'), ('holdfast', 'Holdfast'), ('prov', 'Holdfast strict')):
    for cor in ('mixed', 'unknown'):
        a = alert_stats(cfg, cor); tab.append([lab, cor, str(a['und']), str(a['al']), str(a['rec']), str(a['noal'])])
table([['Preset', 'Corpus', 'Trials not frozen', 'with an alert', 'all originals restored by rollback', 'no alert']] + tab, [1.3, 0.8, 1.0, 0.9, 1.5, 0.7], size=8.5, caption='**Table 5.** Trials in which the attacker was never frozen (hard detection), and what the operator could do afterwards. "Rollback" is `rrfs_ctl promote recover` (a checkpoint rebuilt from the original-byte ring) followed by `rollback`.')
para(f'A freeze is not the only way for the system to protect data: when the evidence is weaker the daemon raises an alert (soft detection, ambiguity event or cluster tier), takes a checkpoint rebuilt from the ring, and withholds the process\'s commits for 30 s. In the default build, {A_h["rec"]} of the {A_h["al"]} alerted trials that were never frozen ended with every original restored after a rollback ({A_hm["rec"]} of {A_hm["al"]} on the mixed corpus, {A_hu["rec"]} of {A_hu["al"]} on the unknown corpus). The remaining {A_h["noal"]} undetected trials raised no alert, so nothing prompted an operator to act; they remain recoverable if the operator runs the recovery anyway (Table 6). Table 5 shows the same figure for the other presets: the checkpoint-and-rollback path is part of the shared code and is also used by the baselines when they alert, so the number that distinguishes the presets is the share of trials in which an alert was raised at all, not the success of the rollback. This is an operator-in-the-loop result: the rollback in our harness is run by a script, and a real alert has to reach a human or a policy in time.')

bl = list(__import__('csv').DictReader(open(os.path.join(RESULTS, 'blind', 'blind.csv'))))
bg2 = collections.defaultdict(list)
for r in bl: bg2[(r['corpus'], r['attack'])].append(r)
BLBL = {'hex_lowentropy': 'Encode as hex', 'daemonized_per_file': 'Double-forked process per file', 'forked_per_file': 'Child process per file', 'exfil_delete': 'Copy out, delete original', 'multi_hex_4': 'Hex-encode, 4 passes per file', 'multi_hex_8': 'Hex-encode, 8 passes per file', 'multi_hex_9': 'Hex-encode, 9 passes per file', 'multi_hex_12': 'Hex-encode, 12 passes per file'}
rows = [['Attack', 'Corpus', 'Frozen', 'Alert only', 'No alert', 'Originals restored by blind recover']]
for a in BLBL:
    for cor in ('mixed', 'unknown'):
        v = bg2[(cor, a)]; n = len(v)
        fz = sum(int(x['detected']) for x in v); al = sum(1 for x in v if not int(x['detected']) and int(x['alert'])); na = n - fz - al
        rows.append([BLBL[a], cor, f'{fz}/{n}', f'{al}/{n}', f'{na}/{n}', f'{sum(int(x["intact_after_blind_recover"]) == int(x["n"]) for x in v)}/{n}'])
table(rows, [2.0, 0.8, 0.7, 0.9, 0.8, 1.6], size=8.5, caption='**Table 6.** Attackers that evade the default detectors, followed by a "blind" recovery: after the attacker ended and the daemon settled, the operator runs `rrfs_ctl promote recover` and `rollback` without any alert to go on. 6 trials per cell, holdfast preset.')
nb = len(bl); nrec = sum(int(x['intact_after_blind_recover']) == int(x['n']) for x in bl); nfz = sum(int(x['detected']) for x in bl); nna = sum(1 for x in bl if not int(x['detected']) and not int(x['alert']))
para(f'**Recovery that does not depend on detection.** The 18 trials of Table 5 that raised no alert lost data only in the sense that no one was told. Table 6 removes the alert from the picture: for eight attackers that include the three that no alert covers on unknown-format data, the operator rebuilt a checkpoint from the original-byte ring and rolled back, and every original was restored in all {nrec} of {nb} trials. Of these trials {nfz} were frozen, {nb - nfz - nna} raised only an alert and {nna} raised nothing, and the attackers that rewrote each file 4, 8, 9 or 12 times did not defeat the ring: the ring keeps the oldest preserved copy of each file, so repeated overwrites do not push the original out. This is the sense in which loss is bounded when the detector misses: the bytes are still there as long as the ring retains them. Two limits apply. First, the ring is pruned as generations rotate (`ring_size`, 8 by default, and periodic baseline checkpoints every 60 s by default); the evaluation harness disabled periodic checkpoints, so these runs had no pruning, and in a short-window variant (2 s interval, ring size 3, 20 trials) every original was still restorable after waits of 0, 4, 12 and 30 s, so we did not find the expiry and make no claim about how long originals stay recoverable. Second, someone has to decide to run the command: the harness runs it unconditionally, and a real deployment needs a person, an alert or a policy to do so, and to do it before the ring is pruned.')

H2('5.5  False positives on benign workloads')
rows = [['Preset', 'Workloads frozen', '95% interval', 'Trials frozen', 'Per-suite frozen (S1 / S2 / S3 / S4)']]
for cfg, lab in (('restore_only', 'restore-only'), ('redirect_only', 'redirect-only'), ('holdfast', 'Holdfast'), ('prov', 'Holdfast strict')):
    f = FPT[cfg]; rows.append([lab, f'{f["frozen"]} of {f["workloads"]}', wil(f['frozen'], f['workloads']), f'{f["frozen_trials"]} of {f["trials"]}', ' / '.join(str(len(FD.FP[(cfg, s)]['frozen'])) for s in ('s1', 's2', 's3', 's4'))])
table(rows, [1.3, 1.1, 1.2, 1.0, 1.9], size=8.5, caption=f'**Table 7.** Benign suites S1 to S4 ({NWL} workloads, 3 repetitions each). Intervals are Wilson 95% over workloads; 0 of n has an upper bound of about 3/n.')
dh = sorted(w for s in ('s1', 's2', 's3', 's4') for w in FD.FP[('holdfast', s)]['deferred'])
fr_r = sorted(w for s in ('s1', 's2', 's3', 's4') for w in FD.FP[('restore_only', s)]['frozen'])
fr_d = sorted(w for s in ('s1', 's2', 's3', 's4') for w in FD.FP[('redirect_only', s)]['frozen'])
para(f'Holdfast froze none of the {NWL} workloads in {fp_h["trials"]} trials (95% upper bound {hi(0, fp_h["workloads"])} per workload and {hi(0, fp_h["trials"])} per trial); strict mode likewise. Restore-only froze {fp_r["frozen"]} ({", ".join(fr_r)}) and redirect-only {fp_d["frozen"]} ({", ".join(fr_d)}). They include image re-encoders, rsync-style copies, in-place text edits and package-style binary replacement, which the baselines\' scores cannot tell from encryption; the cost of the extra signals of Holdfast is that these cases are resolved by the ambiguity policy instead of by a freeze. Not freezing is not the same as being invisible: in {len(dh)} Holdfast workloads ({", ".join(dh)}) the commit of the held writes was deferred by the ambiguity policy for up to 30 s, so a user would see the old version for that long. Zero of {NWL} bounds our suites, not a deployment: the workloads are not an i.i.d. sample of real use.')
rows = [['Adversarial workload (S5)', 'Holdfast: frozen', 'Strict: frozen']]
for w in S5W:
    def fz(c): return 'yes' if any(int(x['detections'] or 0) > 0 or x['error'] for x in FD.S5[(w, c)]) else 'no'
    rows.append([w.replace('_', ' '), fz('holdfast'), fz('prov')])
table(rows, [3.5, 1.4, 1.4], size=8.5, caption='**Table 8.** S5: look-alikes for the provenance signal. Some read (compare, checksum, hash, re-encrypt) their destination file and then overwrite it with high-entropy bytes; others are controls (a copy that never reads, edits of structured files). 3 repetitions each.')
para(f'In strict mode {len(S5P)} of the {len(S5W)} S5 workloads are frozen ({", ".join(w.replace("_", " ") for w in S5P)}): a program that hashes or compares its destination and then overwrites it with new noise-like content performs, as far as the filesystem can tell, the same sequence as ransomware. These are not edge cases that can be fixed by a threshold; they are the price of the signal, and the reason it is off by default. The shelve-and-release path exists for them (Sec. 5.7). The default build freezes none of S5, and the workloads that read and rewrite compressible or structured files (text, JPEG recompression, gzip recompression, container page rewrites) are not frozen in either mode.')

H2('5.6  Adaptive-attacker search')
rows = [['Corpus', 'Preset', 'Trials', 'Frozen', 'Cluster alert', 'Mean loss, no action', 'Mean loss after rollback', 'Trials still losing over 25%']]
for cor in ('mixed', 'unknown'):
    for cfg, lab in (('restore_only', 'restore-only'), ('redirect_only', 'redirect-only'), ('holdfast', 'Holdfast')):
        a = ada(cfg, cor); rows.append([cor, lab, str(a['n']), str(a['det']), str(a['cl']), pct(a['m']), pct(a['m2']), str(a['big2'])])
table(rows, [0.8, 0.9, 0.6, 0.6, 0.8, 1.0, 1.2, 1.1], size=8.5, caption='**Table 9.** 40 randomized attackers per corpus: 1 to 16 cooperating workers, in-place / truncate / rename-over / copy-and-delete, 256 B to 64 KB chunks, 0 to 1 s pacing, 10% to 100% coverage, and single, forked, setsid or double-forked spawning. "Mean loss, no action" is the share of original files not byte-identical in the backing store after the attacker ended and the daemon settled; "after rollback" applies `rollback` to the newest checkpoint if the daemon raised a detection or a cluster alert.')
worst = [r for r in adm['rows'] if int(r['lost_after_recovery']) > 0]
un_nal = [r for r in adu['rows'] if int(r['cluster']) == 0 and int(r['detected']) == 0]
para(f'The search is a random sample of a parameter space we chose, not an optimization against the detector, and with 40 samples per cell it cannot rule out stronger attackers. On the mixed corpus Holdfast froze {adm["det"]} of 40 attackers and the mean loss without any action was {pct(adm["m"])} against {pct(arm["m"])} for restore-only; with a rollback to the alert checkpoint no mixed-corpus trial of any preset lost files ({len(worst)} of 40 still lost files for Holdfast). The structural difference is the loss before anyone acts: {adm["zero"]} of 40 Holdfast attackers had no loss at all against {arm["zero"]} for restore-only. On the unknown corpus the Sec. 5.3 blind spot dominates: Holdfast froze {adu["det"]} of 40, lost {pct(adu["m"])} without action and {pct(adu["m2"])} after rollback, and {len(un_nal)} of 40 attackers triggered neither a detection nor a cluster alert (redirect-only: {pct(aru["m"])} loss, {pct(aru["m2"])} after rollback). The unknown-corpus column is therefore the weak spot of the default build; strict mode was not included in the search because the search attackers write without reading.')

H2('5.7  The release path, crash recovery and the damage-rate bound')
rl = FD.release()
para(f'**Release.** (A) A benign job that writes a temporary file for each of 20 documents and renames it over the document was frozen on a hard detection (hard detection and repair: {rl["A"]["live_intact_after_detect"]} of {rl["A"]["of"]} originals intact in the live view). `rrfs_ctl release` put the job\'s files back ({rl["A"]["live_changed_after_release"]} live files changed back to the job\'s versions), kept the {rl["A"]["restored_versions_kept_in_undo"]} restored originals in an undo directory, and resumed the stopped job ("{rl["A"]["ctl"]}"). (B) A benign job that rewrites 20 files in place was frozen, its writes shelved and the daemon killed with SIGKILL: the manifest had been written, all {rl["B"]["store_intact_after_crash"]} of {rl["B"]["of"]} originals were intact in the backing store, and after a restart `release` on the old process id committed the {rl["B"]["files_committed_by_release_after_restart"]} shelved writes that had been recorded (the rest were dropped, as designed, so the store kept their previous version). A false positive therefore costs a stop and a release, not data.')
bd = list(__import__('csv').DictReader(open(os.path.join(RESULTS, 'final', 'bound.csv'))))
bg = collections.defaultdict(list)
for r in bd: bg[(r['attack'], r['cfg'])].append(r)
rows = [['Pacing (files/s)', 'Holdfast: frozen, files touched', 'Holdfast: store intact', 'Restore-only: frozen, files touched', 'Restore-only: store intact']]
for rate in ('0.5', '1.0', '2.0', '5.0', '20.0'):
    row = [rate]
    for cfg in ('holdfast', 'restore_only'):
        v = bg[(f'rate_{rate}', cfg)]; dt = sum(int(x['detected'] or 0) for x in v); n = len(v)
        ft = sorted({x['files_touched_before_detect'] for x in v if x['files_touched_before_detect']})
        du = _st.mean(int(x['durable_intact_no_recovery']) / int(x['nfiles']) for x in v)
        row += [f'{dt}/{n}, ' + (('/'.join(ft)) if ft else 'n/a'), pct(du)]
    rows.append(row)
table(rows, [1.0, 1.5, 1.2, 1.5, 1.2], size=8.5, caption='**Table 10.** Single attacker overwriting one file with random bytes every 1/r seconds, 5 trials per cell on the mixed corpus, 17 to 23 files per trial.')
para('The analytic bound of Sec. 3.9 allows 7 distinct files per 300 s window before the slow-burn signal fires. In this experiment the content-delta score itself froze the attacker after 3 or 4 files at every pace from 0.5 to 20 files per second, so the bound was never the binding mechanism, and the held writes left every original intact in the store. Restore-only did not freeze the attacker at 1 file/s or slower and lost everything. We did not test paces below 0.5 files/s where the slow-burn signal would be the only mechanism, and the bound does not apply when an attack carries no content evidence (Sec. 5.3).')

H2('5.8  Durability and overhead')
ol = [l for l in open(os.path.join(RESULTS, 'overhead.txt')).read().splitlines() if l.startswith(('direct', 'rrfs'))]
def nums(l): return l.split(':')[1].split()
rows = [['Configuration', 'New 64 MB file', 'Overwrite 32 MB in place', 'Create 1,000 small files', 'Overwrite 1,000 small files']]
for l, lab in zip(ol, ('Direct (no FUSE)', 'Holdfast, hold-back off', 'Holdfast, hold-back on')): rows.append([lab] + [f'{float(x):.2f} s' for x in nums(l)])
table(rows, [1.7, 1.1, 1.4, 1.3, 1.4], size=8.5, caption='**Table 11.** Wall-clock seconds, median of 3, detection disabled by a huge threshold, 2-vCPU VM.')
para('Holdfast is slow on this VM: FUSE alone costs about 14 times the direct time for writing a new 64 MB file and 2 to 3 times for the other three patterns, and hold-back adds a further factor of 3.6 when 1,000 small files are overwritten, because each overwrite makes a pending copy. These are micro-benchmarks of write-heavy patterns; we did not measure application-level benchmarks, so we make no claim about perceived overhead, and we do not claim a performance advantage over any published system. **Durability.** Hold-back has a window: a benign edit acknowledged to the application 0.5 s before the daemon is killed was lost (the file on disk still held the previous version), whereas without hold-back it was already on disk. An fsync commits the held file at once, and the window is the commit delay (2 s, or 30 s after an ambiguity alert). **Faster copy (opt-in, holdback_fast_copy).** Pending copies can be made with a reflink (`FICLONE`) or an in-kernel `copy_file_range` instead of a read/write loop. On this VM (ext4, no reflinks) it gave no measurable change (median of 5: 4 KiB edit of a 48 MB file 0.022 s without and 0.019 s with; touching 100 files of 1 MB 0.44 s and 0.41 s; overwriting 1,000 small files 0.52 s and 0.53 s), which is within the noise of this VM, so we report a null result; the reflink path itself could not be exercised because no reflink-capable filesystem was available, and the expected benefit there (no data copied) is untested. Re-running the attack matrix (228 trials) and the four benign suites with the option on gave results identical to the default in every attack cell and 0 of 110 workloads frozen, so the option does not change decisions. The main evaluation ran on the source whose hashes are in `CODE_FREEZE_SHA256_final.txt`; the shipped source differs only in the three files that implement this opt-in path (`CODE_FREEZE_SHA256_final2.txt`), and the option is off by default. A mid-attack daemon crash was also tried, but all 12 originals were intact with and without hold-back (the attacker had not written yet when the daemon was killed), so the run does not discriminate and we draw no conclusion from it.')

H1('6  Discussion and Limitations')
bullets([
 '**Novelty.** Write redirection with verdict-based commit is Redemption\'s idea [6]; shadow copy plus restore is ShieldFS\'s [5]. Holdfast\'s contribution is the controlled comparison in one code base, the hybrid with a journaled undo, the graded response with shelving and release, the cumulative and process-tree signals, the damage-rate analysis, the read-provenance signal and the negative results. A targeted literature search in October 2026 (deferred-commit or hold-back file systems, graded response, false-positive evaluation) found no system that combines these elements; the closest are GuardFS [7], VaultFS [12], SHIELD [10] and the access-control system of [18], and the search was not exhaustive. The baselines are our re-implementations of principles; the originals are Windows kernel components and could not be run on this Linux testbed.',
 '**Blind spots.** Noise-over-noise overwrites of unknown-format data are deferred and alerted but not frozen by the default build (Sec. 5.3); the opt-in read-provenance mode freezes read-then-encrypt attackers but not wipers that never read their targets, and it freezes look-alike tools that hash or compare before overwriting (Sec. 5.5). Per-file processes with no common parent, copy-out-and-delete and entropy-capped encoding of plain text are not frozen by any configuration (Sec. 5.2, 5.3); for the first two the daemon raises an alert, for hex encoding of unknown-format data it does not.',
 '**Bound limits.** The damage-rate bound (Sec. 3.9) is a rate, not a total; it needs content evidence and a common non-init parent for split attackers, and we tested it only down to 0.5 files/s.',
 '**Recovery needs an operator, and a retention window we did not bound.** Every recovery in Tables 5 and 6 is a rollback run by our harness. A deployment needs an alert channel, or a person who suspects damage, and a person or policy that acts before the ring is pruned; the 30 s deferral only buys time, and we did not find the point at which originals expire (Sec. 5.4).',
 '**Not tamper-resistant.** Root or any process under the daemon\'s uid can kill the daemon, edit the backing directory or resume a stopped process. Running the daemon as a dedicated user with a 0700 backing directory narrows this (the project README gives the steps) but does not remove it, and we did not evaluate it.',
 '**Durability window.** Acknowledged benign writes held for up to the commit delay (2 s, or 30 s in the ambiguous case) are lost if the daemon crashes; the backing store then holds the previous version (Sec. 5.8). Shelved writes of a flagged process are recorded in a manifest and survive a crash (Sec. 5.7).',
 '**Cost.** Whole-file holding and FUSE overhead are large on our VM (Sec. 5.8); files over 64 MB bypass hold-back.',
 '**Reliability claims.** The 0-of-110 figure bounds false positives on our four suites only. The suites were written by the author, rules were refined after seeing failures on them, and tools and workloads we did not think of are not covered; no long-running real-user trace was replayed. Reliability was bought partly by weakening responses: rename-only activity no longer freezes anyone, and ambiguous overwrites are deferred rather than frozen.',
 '**Evaluation.** Synthetic attackers, our own baselines, one 2-vCPU VM, 6 trials per attack cell, no real ransomware, no kernel-level or SSD-level comparison, and a harness whose operator actions (release, rollback) are scripted.',
])
H1('7  Future Work')
para('(1) Run real ransomware families in an isolated lab, and compare with ports of the original Windows systems where their authors permit it; (2) replay public I/O traces for false-positive rates on real machines; (3) signals for copy-out-and-delete and for wipers that never read their targets; (4) block-level or reflink-based holding to cut the whole-file cost; (5) a separate-account or kernel-resident variant for tamper resistance; (6) an alert channel and a measured time-to-action study with real operators.')
H1('8  Conclusion')
para(f'In one Linux code base, hold-back and restore-after-detect protect different parts of the problem: hold-back keeps overwritten files intact at the freeze, restore handles replace, delete and rename after the fact, and the hybrid with a slow-burn signal and process-tree aggregation covers the paced and per-child-process attackers that defeat both principles on their own. Making false positives the top constraint changed the design: a freeze needs content evidence on two files, flagged writes are shelved so a false positive can be released, and weaker signals only hold, checkpoint or alert. On our suites that gave {fp_h["frozen"]} frozen workloads of {NWL}, against {fp_r["frozen"]} and {fp_d["frozen"]} for the two baseline principles, and {hf_m} of {len(ATTACKS_ALL)} attack styles frozen with every original intact on recognizable formats, at the price of not freezing rename-only activity and of deferring instead of freezing noise-over-noise overwrites. An opt-in read-provenance signal closes much of the latter gap for read-then-encrypt attackers and has a measured cost on adversarial look-alikes. Per-file processes without a common parent, copy-out-and-delete and the wipers on unknown-format data remain open. We describe the testbed, the attacker and benign suites and the numbers in enough detail to serve as a basis for the next comparison, not as a replacement for the published systems.')

H1('9  Code and Data Availability')
para('The source code, the evaluation harness (attackers, benign workloads, presets and run scripts) and all result data behind the tables are published at ' + CODE_URL + ' under the MIT license. The repository contains: the daemon and operator tool (C++17, FUSE3), eleven unit-test suites and two ThreadSanitizer stress programs; `eval/` with the harness, the run scripts (`run_evaluation.sh` reproduces every table; it takes many hours on a 2-vCPU machine and is resumable) and `eval/results/` with the CSV and JSON files that the tables are computed from; and `paper/` with this paper and the script that builds its tables from `eval/results/`. The main evaluation ran on the source whose hashes are in `eval/CODE_FREEZE_SHA256_final.txt`; the repository differs from it only by the opt-in copy path of Sec. 5.8 (`CODE_FREEZE_SHA256_final2.txt`) and by comments (the compiled binaries are byte-identical after stripping). No third-party datasets or real malware were used. The synthetic attackers in the repository only modify files that they or the harness create inside a scratch directory; they are intended for use on a throw-away mount.')

H1('References')
refs=[
 '[1] N. Scaife, H. Carter, P. Traynor, K. R. B. Butler, "CryptoLock (and Drop It): Stopping Ransomware Attacks on User Data," in Proc. IEEE 36th Int. Conf. Distributed Computing Systems (ICDCS), 2016, doi:10.1109/ICDCS.2016.46.',
 '[2] A. Kharraz, S. Arshad, C. Mulliner, W. Robertson, E. Kirda, "UNVEIL: A Large-Scale, Automated Approach to Detecting Ransomware," in Proc. 25th USENIX Security Symposium, 2016, pp. 757-772.',
 '[3] D. Sgandurra, L. Munoz-Gonzalez, R. Mohsen, E. C. Lupu, "Automated Dynamic Analysis of Ransomware: Benefits, Limitations and use for Detection," arXiv:1609.03020, 2016.',
 '[4] S. Homayoun, A. Dehghantanha, M. Ahmadzadeh, S. Hashemi, R. Khayami, "Know Abnormal, Find Evil: Frequent Pattern Mining for Ransomware Threat Hunting and Intelligence," IEEE Trans. Emerging Topics in Computing, vol. 8, no. 2, pp. 341-351, 2020.',
 '[5] A. Continella, A. Guagnelli, G. Zingaro, G. De Pasquale, A. Barenghi, S. Zanero, F. Maggi, "ShieldFS: A Self-healing, Ransomware-aware Filesystem," in Proc. 32nd Annual Computer Security Applications Conf. (ACSAC), 2016, doi:10.1145/2991079.2991110.',
 '[6] A. Kharraz, E. Kirda, "Redemption: Real-time Protection Against Ransomware at End-Hosts," in Proc. 20th Int. Symp. Research in Attacks, Intrusions and Defenses (RAID), Atlanta, GA, Sept. 2017.',
 '[7] J. von der Assen, C. Feng, A. Huertas Celdran, R. Oles, G. Bovet, B. Stiller, "GuardFS: a File System for Integrated Detection and Mitigation of Linux-based Ransomware," J. Information Security and Applications, vol. 93, 2025, doi:10.1016/j.jisa.2025.104078; arXiv:2401.17917.',
 '[8] S. Mehnaz, A. Mudgerikar, E. Bertino, "RWGuard: A Real-Time Detection System Against Cryptographic Ransomware," in RAID 2018, LNCS vol. 11050, pp. 114-136.',
 '[9] C. van Sloun, V. Woeste, K. Wolsing, J. Pennekamp, K. Wehrle, "Detecting Ransomware Despite I/O Overhead: A Practical Multi-Staged Approach," in Proc. NDSS, 2025.',
 '[10] M. Raz, V. S. C. Putrevu, P. Krishnamurthy, F. Khorrami, R. Karri, "SHIELD: A Host-Independent Framework for Ransomware Detection using Deep Filesystem Features," arXiv:2501.16619.',
 '[11] J. Huang, J. Xu, X. Xing, P. Liu, M. K. Qureshi, "FlashGuard: Leveraging Intrinsic Flash Properties to Defend Against Encryption Ransomware," in Proc. ACM CCS, Dallas, TX, 2017, pp. 2231-2244, doi:10.1145/3133956.3134035.',
 '[12] P. Caporaso, G. Bianchi, F. Quaglia, "VaultFS: Write-once Software Support at the File System Level Against Ransomware Attacks," arXiv:2410.21979, 2024 (preprint; we found no peer-reviewed version).',
 '[13] libfuse project, https://github.com/libfuse/libfuse. Accessed 16 Oct 2026.',
 '[14] F. De Gaspari, D. Hitaj, G. Pagnotta, L. De Carli, L. V. Mancini, "The Naked Sun: Malicious Cooperation Between Benign-Looking Processes," arXiv:1911.02423, 2019.',
 '[15] Y. Ineza, G. Jackson, P. Niyonkuru, J. Kevil, A. Serwadda, "Intermittent File Encryption in Ransomware: Measurement, Modeling, and Detection," arXiv:2510.15133, v2, 2026.',
 '[16] M. Hirano, R. Kobayashi, "Evasive Ransomware Attacks Using Low-level Behavioral Adversarial Examples," arXiv:2508.08656, 2025.',
 '[17] A. Brodzik, T. Malec-Kruszynski, W. Niewolski, M. Tkaczyk, K. Bocianiak, S.-Y. Loui, "Ransomware Detection Using Machine Learning in the Linux Kernel," arXiv:2409.06452, 2024.',
 '[18] K. Begovic, A. Al-Ali, Q. Malluhi, "Building a Robust Risk-Based Access Control System to Combat Ransomware\'s Capability to Encrypt," arXiv:2601.16795, Qatar University (preprint; no venue found).',
]
for r in refs: p=para(r, size=10); p.paragraph_format.left_indent=Inches(0.3); p.paragraph_format.first_line_indent=Inches(-0.3)

H1('Appendix A  Configuration Parameters')
table([['Key','Default','Meaning'],
 ['promote_threshold / decay_per_second','10.0 / 0.5','Detection threshold / score decay'],
 ['w_entropy / w_overwrite_burst / w_ext_churn / w_type_destroyed','1 / 2 / 3 / 3','Signal weights'],
 ['entropy_high_water / entropy_jump_min','7.5 / 1.0','Entropy level that counts / minimum rise over the original'],
 ['burst_file_threshold / window_seconds','6 / 5','Distinct corroborated paths per window'],
 ['slow_burn_files / slow_window_seconds','8 / 300','Rate-independent distinct-file signal'],
 ['aggregate_by_parent','true','Also score the parent process bucket'],
 ['holdback_enabled / holdback_commit_delay_ms / holdback_commit_score_frac','true / 2000 / 0.5','Hold-back and its commit rule'],
 ['holdback_max_file_mb / holdback_max_files','64 / 256','Size limit / force-commit cap'],
 ['repair_on_detect / content_delta_enabled','true / true','Scoped repair with quarantine / content delta'],
 ['ambiguous_policy / ambiguous_files / ambiguous_defer_ms','defer / 8 / 30000','Noise-over-noise policy (off, defer, freeze)'],
 ['graded_response / hard_min_content_files','true / 2','Soft/hard tiers; content-evidence files needed to freeze'],
 ['shelve_on_detect / type_conversion_benign','true / true','Keep flagged writes for release; known-format to known-format is not destruction'],
 ['cluster_hold / cluster_defer_ms','true / 30000','Cooperation-aware hold tier / commit withholding time'],
 ['cluster_min_files / cluster_min_pids / global_min_files','8 / 3 / 16','Cluster triggers'],
 ['bulk_delete_alert_files','16','Alert-only bulk-delete rule (0 = off)'],
 ['soft_hold / soft_hold_ms / soft_checkpoint','true / 30000 / true','After a soft or ambiguous alert: withhold that process\'s commits, and take a checkpoint rebuilt from the ring'],
 ['holdback_fast_copy','false','Opt-in: make pending copies with FICLONE or copy_file_range before the read/write loop (no measured benefit on ext4)'],
 ['log_writes','true','Per-write events in events.log (false = smaller log; detections are always logged)'],
 ['read_provenance / provenance_window_ms / provenance_min_hamming','false / 120000 / 0.35','Opt-in strict mode: read-then-overwrite with unrelated high-entropy bytes counts as destroyed content; how long a read counts; minimum fraction of differing bits'],
 ['ring_size / suspend_on_detect','8 / true','Copy-on-write generations / SIGSTOP the offender']],
 [2.9,1.2,2.4], caption='**Table A1.** Parameters read from rrfs.conf.')
doc.save(os.path.join(HERE, 'Holdfast_conference_paper.docx')); print('saved')
