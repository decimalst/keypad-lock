#!/usr/bin/env python3
"""Render README figures from shared drawing primitives and the tested demo transcript.
Requires Pillow 12.3.0. Set --font/--bold-font to local TrueType font paths if needed.
No illustrative hardware photos or invented runtime output are used.
"""
import argparse
import html
import re
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/assets'
parser = argparse.ArgumentParser()
parser.add_argument('--font')
parser.add_argument('--bold-font')
args = parser.parse_args()

def font_path(custom, bold=False):
    candidates = [custom] if custom else [
        '/System/Library/Fonts/Supplemental/Arial Bold.ttf' if bold else '/System/Library/Fonts/Supplemental/Arial.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf' if bold else '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        'C:/Windows/Fonts/arialbd.ttf' if bold else 'C:/Windows/Fonts/arial.ttf',
    ]
    return next(str(p) for p in candidates if p and Path(p).exists())
FONTS = [font_path(args.font), font_path(args.bold_font, True)]
BG='#0b1220'; PANEL='#121e30'; STROKE='#2b3b52'; WHITE='#eef4fc'; MUTED='#a4b5cc'; GREEN='#73e0bf'; BLUE='#84baff'; AMBER='#ffcf83'
class Canvas:
    def __init__(self,w=1600,h=1000):
        self.im=Image.new('RGB',(w,h),BG);self.d=ImageDraw.Draw(self.im)
        self.svg=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="Keypad lock architecture">',f'<rect width="{w}" height="{h}" fill="{BG}"/>']
    def box(self,x,y,w,h,fill=PANEL,outline=STROKE,r=18):
        self.d.rounded_rectangle((x,y,x+w,y+h),radius=r,fill=fill,outline=outline,width=2)
        self.svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{outline}" stroke-width="2"/>')
    def text(self,x,y,t,size=24,color=WHITE,bold=False):
        font=ImageFont.truetype(FONTS[int(bold)],size)
        self.d.text((x,y),t,font=font,fill=color,anchor='lt')
        self.svg.append(f'<text x="{x}" y="{y+size*.82}" fill="{color}" font-family="Arial, sans-serif" font-size="{size}" font-weight="{700 if bold else 400}">{html.escape(t)}</text>')
    def line(self,points,color=GREEN,arrow=False):
        self.d.line(points,fill=color,width=3)
        self.svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{color}" stroke-width="3"/>')
        if arrow:
            x,y=points[-1];px,py=points[-2]
            tip=[(x,y),(x-12,y-7),(x-12,y+7)] if x>px else ([(x,y),(x-7,y-12),(x+7,y-12)] if y>py else [(x,y),(x-7,y+12),(x+7,y+12)])
            self.d.polygon(tip,fill=color)
            self.svg.append(f'<polygon points="{" ".join(f"{a},{b}" for a,b in tip)}" fill="{color}"/>')
    def save(self,name):
        self.im.save(OUT/f'{name}.png')
        (OUT/f'{name}.svg').write_text('\n'.join(self.svg+['</svg>']))

OUT.mkdir(parents=True,exist_ok=True)
c=Canvas()
c.text(64,48,'DECIMALST  /  RUST SYSTEMS',20,GREEN,True)
c.text(64,100,'A small lock. Explicit boundaries.',60,WHITE,True)
c.text(64,186,'Deterministic decisions in Rust. Hardware effects at the edge.',29,MUTED)
for x,t in [(64,'Rust 2024'),(280,'no_std'),(462,'No heap in core'),(757,'No unsafe')]:
    width={'Rust 2024':192,'no_std':158,'No heap in core':272,'No unsafe':190}[t]
    c.box(x,247,width,46,fill='#14283a');c.text(x+18,259,t,21,BLUE)
# Input, core, output cards.
c.box(64,363,350,252)
c.text(90,390,'01 / INPUT ADAPTER',18,BLUE,True)
c.text(90,433,'Events',35,WHITE,True)
for y,t in [(488,'Keypad  ·  submit  ·  clear'),(528,'Debounced door sensor'),(568,'Monotonic elapsed time')]:c.text(90,y,t,23,MUTED)
c.box(518,341,536,296,fill='#102c31',outline='#448d80')
c.text(546,368,'02 / PURE RUST CORE',18,GREEN,True)
c.text(546,411,'SecurityState::next(event)',30,WHITE,True)
c.text(546,466,'Current state → next state + actions',23,GREEN)
c.line([(546,510),(1026,510)],'#315c60')
c.text(546,539,'PIN policy  ·  retry budget  ·  timers',23,MUTED)
c.text(546,579,'Bounded buffers  ·  zeroized secrets',23,MUTED)
c.box(1158,363,378,252)
c.text(1184,390,'03 / OUTPUT EXECUTOR',18,BLUE,True)
c.text(1184,433,'Actions',35,WHITE,True)
for y,t in [(488,'Bolt  ·  alarm  ·  display'),(528,'Apply only output changes'),(568,'Sync all outputs on boot')]:c.text(1184,y,t,23,MUTED)
c.line([(414,489),(505,489)],arrow=True);c.line([(1054,489),(1145,489)],arrow=True)
c.text(431,456,'Event',18,GREEN);c.text(1067,456,'Action',18,GREEN)
c.line([(786,637),(786,711)],arrow=True)
c.box(518,724,1018,140)
c.text(546,748,'PERSISTENCE BOUNDARY',18,AMBER,True)
c.text(546,786,'Snapshot + PasscodeSealer → platform storage',27,WHITE,True)
c.text(546,829,'Adapter owns encryption, metadata authentication and anti-rollback.',21,MUTED)
c.text(64,729,'Same core.',31,WHITE,True)
c.text(64,773,'Host simulation.',26,MUTED)
c.text(64,811,'Embedded integration.',26,MUTED)
c.line([(64,914),(1536,914)],STROKE)
c.text(64,943,'github.com/decimalst/keypad-lock',22,MUTED)
c.text(1060,943,'LOGIC DEMO / HARDWARE NOT INCLUDED',17,GREEN,True)
c.save('architecture')
# Read actual program output: assertions fail if its schema changes.
rows=[]
for line in (ROOT/'docs/demo.txt').read_text().splitlines():
    m=re.fullmatch(r'(\d+)  (.*?)\s+(Setup|Locked|Unlocked|Lockout|Alarm)\s+bolt=(LOCKED|RELEASED)\s+alarm=(off|ON)',line)
    if m: rows.append(m.groups())
assert len(rows)==12, 'Refresh parser after changing the demo transcript'

def demo_frame(upto):
    c=Canvas(1600,1000)
    c.text(64,48,'KEYPAD LOCK / LIVE RUST TRANSCRIPT',20,GREEN,True)
    c.text(64,99,'Watch the policy do the work.',58,WHITE,True)
    c.text(64,180,'A reproducible host simulation. No hardware. No sleeps. No PIN logging.',26,MUTED)
    c.box(64,244,1472,642)
    c.text(90,269,'$ cargo run --locked --quiet',23,GREEN)
    c.text(90,321,'STEP',16,MUTED,True);c.text(182,321,'EVENT',16,MUTED,True)
    c.text(915,321,'STATE',16,MUTED,True);c.text(1150,321,'BOLT',16,MUTED,True);c.text(1400,321,'ALARM',16,MUTED,True)
    for i,(step,label,state,bolt,alarm) in enumerate(rows):
        y=367+i*41
        if i>upto: continue
        accent=AMBER if alarm=='ON' else GREEN if bolt=='RELEASED' else WHITE
        if i==upto:c.box(80,y-8,1440,38,fill='#213247',outline='#213247',r=6)
        c.text(94,y,step,21,MUTED);c.text(182,y,label,23,WHITE)
        c.text(915,y,state,23,accent,True);c.text(1150,y,bolt,21,accent);c.text(1421,y,alarm,21,accent)
    c.text(64,925,'10s auto-relock',26,GREEN,True);c.text(480,925,'30s retry lockout',26,AMBER,True);c.text(1010,925,'Open door inhibits timed relock',26,BLUE,True)
    return c
frame=demo_frame(11);frame.save('demo')
frames=[demo_frame(i).im.resize((1200,750)) for i in range(len(rows))]
frames[0].save(OUT/'demo.gif',save_all=True,append_images=frames[1:],duration=[1000]*11+[3500],loop=0,optimize=False)
print('Rendered architecture.svg/png, demo.svg/png and demo.gif from docs/demo.txt')
