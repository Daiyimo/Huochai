"""Code-rendered instructional UI for the maintained offline features."""
import io
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


def offline_guide(page):
    fonts=Path(os.environ.get('WINDIR',r'C:\Windows'))/'Fonts'
    regular=fonts/'msyh.ttc'; bold=fonts/'msyhbd.ttc'
    image=Image.new('RGB',(1000,600),'#fff6f1'); draw=ImageDraw.Draw(image)
    def text(x,y,value,size=24,color='#343434',heavy=False):
        font=ImageFont.truetype(str(bold if heavy else regular),size)
        draw.text((x,y),value,font=font,fill=color)
    draw.rounded_rectangle((54,44,122,82),radius=19,fill='#ff5b2b')
    text(73,49,f'0{page}',21,'white',True)
    text(140,47,'火柴 · 离线使用指南',22,'#8b6254')
    if page==2:
        text(54,111,'输入文件名，查找本地文件',40,heavy=True)
        text(56,181,'双击 Ctrl 唤起搜索框，再输入要找的文件名。',24,'#6d625b')
        draw.rounded_rectangle((54,247,946,497),radius=20,fill='white',outline='#efddd4',width=2)
        draw.rounded_rectangle((78,272,922,332),radius=12,fill='#fff0e7')
        text(99,282,'工作总结',29,heavy=True)
        draw.line((82,353,918,353),fill='#f0e4dd',width=2)
        text(101,373,'工作总结.docx',27,heavy=True)
        text(101,421,'本地文件搜索结果示例',21,'#8a817a')
        text(56,532,'本离线版保留本地搜索；网络搜索入口已停用。',22,'#8b6254')
    elif page==3:
        text(54,111,'配置和便签，随程序一起保留',40,heavy=True)
        text(56,181,'移动或备份时，请同时保留下面两项。',24,'#6d625b')
        draw.rounded_rectangle((54,245,946,492),radius=20,fill='white',outline='#efddd4',width=2)
        draw.rounded_rectangle((80,275,130,325),radius=10,fill='#fff0e7')
        text(96,282,'1',26,'#ff5b2b',True)
        text(154,279,'火柴单文件版.exe',29,heavy=True)
        draw.line((82,351,918,351),fill='#f0e4dd',width=2)
        draw.rounded_rectangle((80,378,130,428),radius=10,fill='#fff0e7')
        text(96,385,'2',26,'#ff5b2b',True)
        text(154,375,'HuoChatOffline-v1-single 文件夹',28,heavy=True)
        text(155,423,'Data 内保存便签、索引及经火柴启动的应用数据',21,'#8a817a')
        text(56,530,'退出火柴及由它启动的程序，等待保存完成再移动。',22,'#8b6254')
    else:
        raise ValueError('Unknown offline guide page')
    out=io.BytesIO()
    image.quantize(colors=128).save(out,format='GIF',optimize=True)
    return out.getvalue()
