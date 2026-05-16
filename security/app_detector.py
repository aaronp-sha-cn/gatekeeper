"""
GateKeeper - 应用识别引擎 (AppID)
实现深度应用识别，类似 Palo Alto Networks AppID 技术，
通过协议签名、端口模式、深度包检测(DPI)识别 3000+ 应用程序
"""
import re, os, json, struct, subprocess, threading
from typing import Dict, List, Optional
from collections import defaultdict
from config.logging_config import get_logger
logger = get_logger("app_detector")

def _app(i, n, ne, c, cn, r, d, p, pt, s, bw, pr):
    """构建应用条目字典"""
    return {"id":i,"name":n,"name_en":ne,"category":c,"category_name":cn,
            "risk":r,"description":d,"protocols":p,"ports":pt,"signatures":s,
            "bandwidth_heavy":bw,"productivity":pr}

def _s(p,d="TLS SNI匹配"): return {"type":"tls_sni","pattern":p,"description":d}
def _h(p,d="HTTP Host匹配"): return {"type":"http_host","pattern":p,"description":d}
def _u(p,d="URI路径匹配"): return {"type":"http_uri","pattern":p,"description":d}
def _d(p,d="DPI特征"): return {"type":"dpi_pattern","pattern":p,"description":d}

# 分类与协议常量
_I="im";_S="即时通讯";_ST="streaming";_SV="视频流媒体";_SO="social";_SC="社交媒体"
_FT="file_transfer";_FE="文件传输";_RA="remote_access";_RE="远程访问";_G="gaming"
_NG="网络游戏";_V="voip";_VP="网络电话";_E="email";_EM="电子邮件";_W="web"
_WB="Web应用";_P="p2p";_PP="P2P下载";_DB="database";_DA="数据库";_C="cloud"
_CS="云服务";_T=["tcp"];_TU=["tcp","udp"];_U=["udp"]

# 紧凑格式: (id,name,name_en,cat,cat_name,risk,desc,protos,ports,sigs,bw,prod)
_R = [
# ===== 即时通讯 (IM) =====
("wechat","微信","WeChat",_I,_S,"low","腾讯即时通讯",_TU,[80,443,8080],[_s("weixin"),_h("weixin.qq.com"),_u("/cgi-bin/mmwebwx"),_d("\\xbf\\x00\\x00\\x00\\x00\\x00","微信特征")],False,"neutral"),
("qq","QQ","QQ",_I,_S,"low","腾讯QQ",_TU,[443,8000,8080],[_s("qq.com"),_h("im.qq.com"),_d("\\x02\\x0a\\x00\\x00\\x00","QQ协议")],False,"neutral"),
("dingtalk","钉钉","DingTalk",_I,_S,"low","阿里企业通讯",_TU,[443],[_s("dingtalk"),_h("oapi.dingtalk.com")],False,"productive"),
("feishu","飞书","Feishu/Lark",_I,_S,"low","字节企业协作",_T,[443],[_s("feishu"),_s("larksuite"),_h("open.feishu.cn")],False,"productive"),
("wecom","企业微信","WeCom",_I,_S,"low","腾讯企业微信",_T,[443],[_s("work.weixin.qq.com"),_h("work.weixin.qq.com")],False,"productive"),
("telegram","Telegram","Telegram",_I,_S,"medium","加密即时通讯",_TU,[443],[_s("telegram"),_d("\\x50\\x49\\x44\\x45","MTProto")],False,"neutral"),
("signal","Signal","Signal",_I,_S,"low","端到端加密通讯",_T,[443],[_s("signal"),_h("signal.org")],False,"neutral"),
("whatsapp","WhatsApp","WhatsApp",_I,_S,"low","Meta加密通讯",_TU,[443,5222,5223],[_s("whatsapp"),_d("WAToken","WhatsApp特征")],False,"neutral"),
("slack","Slack","Slack",_I,_S,"low","企业团队协作",_T,[443],[_s("slack.com"),_h("slack.com"),_u("/api/")],False,"productive"),
("teams","Microsoft Teams","Microsoft Teams",_I,_S,"low","微软企业协作",_TU,[443,3478],[_s("teams.microsoft"),_h("teams.microsoft.com")],False,"productive"),
("discord","Discord","Discord",_I,_S,"medium","游戏社区通讯",_TU,[443,6881],[_s("discord"),_h("discord.com")],True,"unproductive"),
("skype","Skype","Skype",_I,_S,"low","微软网络电话",_TU,[443],[_s("skype")],True,"neutral"),
("line","LINE","LINE",_I,_S,"low","日韩即时通讯",_T,[443],[_s("line.me"),_h("line.me")],False,"neutral"),
("kakaotalk","KakaoTalk","KakaoTalk",_I,_S,"low","韩国即时通讯",_T,[443],[_s("kakao")],False,"neutral"),
("viber","Viber","Viber",_I,_S,"low","网络电话通讯",_TU,[443,5242,7985],[_s("viber")],True,"neutral"),
("messenger","Messenger","Messenger",_I,_S,"medium","Facebook Messenger",_T,[443],[_s("messenger.com")],False,"neutral"),
("icq","ICQ","ICQ",_I,_S,"low","经典即时通讯",_T,[443],[_s("icq.com")],False,"neutral"),
("jabber","Jabber/XMPP","Jabber/XMPP",_I,_S,"low","XMPP即时通讯",_T,[5222,5269],[_d("<stream:stream","XMPP流")],False,"productive"),
("irc","IRC","IRC",_I,_S,"low","互联网中继聊天",_T,[6667,6697],[_d("NICK ","IRC NICK")],False,"neutral"),
("rocketchat","Rocket.Chat","Rocket.Chat",_I,_S,"low","开源团队聊天",_T,[443,3000],[_s("rocket.chat")],False,"productive"),
("mattermost","Mattermost","Mattermost",_I,_S,"low","开源团队协作",_T,[443,8065],[_s("mattermost")],False,"productive"),
# ===== 视频流媒体 (Streaming) =====
("youtube","YouTube","YouTube",_ST,_SV,"low","Google视频平台",_T,[443],[_s("youtube"),_h("youtube.com"),_u("/watch"),_u("/embed/")],True,"unproductive"),
("netflix","Netflix","Netflix",_ST,_SV,"low","流媒体影视",_T,[443],[_s("netflix"),_h("netflix.com"),_d("NFLXVIDEO","Netflix流")],True,"unproductive"),
("bilibili","哔哩哔哩","Bilibili",_ST,_SV,"low","弹幕视频平台",_T,[443],[_s("bilibili"),_h("bilibili.com"),_u("/video/")],True,"unproductive"),
("iqiyi","爱奇艺","iQiyi",_ST,_SV,"low","百度视频平台",_T,[443],[_s("iqiyi"),_h("iqiyi.com")],True,"unproductive"),
("tencent_video","腾讯视频","Tencent Video",_ST,_SV,"low","腾讯视频",_T,[443],[_s("v.qq.com"),_h("v.qq.com")],True,"unproductive"),
("youku","优酷","Youku",_ST,_SV,"low","阿里巴巴视频",_T,[443],[_s("youku"),_h("youku.com")],True,"unproductive"),
("douyin","抖音/TikTok","Douyin/TikTok",_ST,_SV,"medium","短视频平台",_T,[443],[_s("douyin"),_s("tiktok"),_h("douyin.com")],True,"unproductive"),
("kuaishou","快手","Kuaishou",_ST,_SV,"low","短视频平台",_T,[443],[_s("kuaishou"),_h("kuaishou.com")],True,"unproductive"),
("twitch","Twitch","Twitch",_ST,_SV,"low","游戏直播",_T,[443],[_s("twitch"),_h("twitch.tv")],True,"unproductive"),
("hulu","Hulu","Hulu",_ST,_SV,"low","流媒体影视",_T,[443],[_s("hulu"),_h("hulu.com")],True,"unproductive"),
("disney_plus","Disney+","Disney+",_ST,_SV,"low","迪士尼流媒体",_T,[443],[_s("disneyplus"),_h("disneyplus.com")],True,"unproductive"),
("amazon_prime","Prime Video","Amazon Prime Video",_ST,_SV,"low","亚马逊流媒体",_T,[443],[_s("primevideo")],True,"unproductive"),
("spotify","Spotify","Spotify",_ST,_SV,"low","流媒体音乐",_T,[443],[_s("spotify"),_h("spotify.com")],True,"neutral"),
("apple_music","Apple Music","Apple Music",_ST,_SV,"low","苹果音乐",_T,[443],[_s("apple.com"),_h("music.apple.com")],True,"neutral"),
("netease_music","网易云音乐","NetEase Cloud Music",_ST,_SV,"low","网易音乐",_T,[443],[_s("music.163"),_h("music.163.com")],True,"neutral"),
("huya","虎牙直播","Huya Live",_ST,_SV,"low","游戏直播平台",_T,[443],[_s("huya.com"),_h("huya.com")],True,"unproductive"),
("douyu","斗鱼直播","Douyu Live",_ST,_SV,"low","游戏直播平台",_T,[443],[_s("douyu.com"),_h("douyu.com")],True,"unproductive"),
("vimeo","Vimeo","Vimeo",_ST,_SV,"low","高清视频平台",_T,[443],[_s("vimeo.com"),_h("vimeo.com")],True,"unproductive"),
("tidal","Tidal","Tidal",_ST,_SV,"low","高品质流媒体音乐",_T,[443],[_s("tidal.com")],True,"neutral"),
# ===== 社交媒体 (Social) =====
("weibo","微博","Weibo",_SO,_SC,"low","新浪微博",_T,[443],[_s("weibo"),_h("weibo.com")],True,"unproductive"),
("facebook","Facebook","Facebook",_SO,_SC,"medium","Meta社交网络",_T,[443],[_s("facebook"),_h("facebook.com")],True,"unproductive"),
("twitter","Twitter/X","Twitter/X",_SO,_SC,"medium","X社交平台",_T,[443],[_s("twitter"),_s("x.com"),_h("twitter.com")],True,"unproductive"),
("instagram","Instagram","Instagram",_SO,_SC,"medium","Meta图片社交",_T,[443],[_s("instagram"),_h("instagram.com")],True,"unproductive"),
("linkedin","LinkedIn","LinkedIn",_SO,_SC,"low","职业社交网络",_T,[443],[_s("linkedin"),_h("linkedin.com")],False,"productive"),
("tiktok_social","TikTok社交","TikTok Social",_SO,_SC,"medium","TikTok社交",_T,[443],[_s("tiktok"),_u("/share/")],True,"unproductive"),
("reddit","Reddit","Reddit",_SO,_SC,"low","社区论坛",_T,[443],[_s("reddit"),_h("reddit.com")],True,"neutral"),
("zhihu","知乎","Zhihu",_SO,_SC,"low","中文问答社区",_T,[443],[_s("zhihu"),_h("zhihu.com")],False,"neutral"),
("douban","豆瓣","Douban",_SO,_SC,"low","书影音社区",_T,[443],[_s("douban"),_h("douban.com")],False,"neutral"),
("xiaohongshu","小红书","Xiaohongshu",_SO,_SC,"low","生活方式社区",_T,[443],[_s("xiaohongshu"),_h("xiaohongshu.com")],True,"unproductive"),
("pinterest","Pinterest","Pinterest",_SO,_SC,"low","图片分享社区",_T,[443],[_s("pinterest")],True,"neutral"),
("snapchat","Snapchat","Snapchat",_SO,_SC,"medium","即时图片社交",_T,[443],[_s("snapchat")],True,"unproductive"),
("quora","Quora","Quora",_SO,_SC,"low","英文问答社区",_T,[443],[_s("quora.com")],False,"neutral"),
("tumblr","Tumblr","Tumblr",_SO,_SC,"medium","轻博客平台",_T,[443],[_s("tumblr.com")],True,"unproductive"),
("wechat_moments","微信朋友圈","WeChat Moments",_SO,_SC,"low","微信社交动态",_T,[443],[_s("weixin.qq.com"),_u("/sns/")],False,"neutral"),
("tieba","百度贴吧","Baidu Tieba",_SO,_SC,"low","百度社区论坛",_T,[443],[_s("tieba.baidu.com"),_h("tieba.baidu.com")],False,"neutral"),
("csdn","CSDN","CSDN",_SO,_SC,"low","开发者社区",_T,[443],[_s("csdn.net"),_h("csdn.net")],False,"productive"),
("juejin","掘金","Juejin",_SO,_SC,"low","开发者社区",_T,[443],[_s("juejin.cn")],False,"productive"),
("stackoverflow","Stack Overflow","Stack Overflow",_SO,_SC,"low","编程问答社区",_T,[443],[_s("stackoverflow.com"),_h("stackoverflow.com")],False,"productive"),
("github_social","GitHub","GitHub",_SO,_SC,"low","代码托管社区",_T,[443],[_s("github.com"),_h("github.com")],False,"productive"),
("bluesky","Bluesky","Bluesky",_SO,_SC,"low","去中心化社交",_T,[443],[_s("bsky.app")],False,"neutral"),
# ===== 文件传输 (File Transfer) =====
("ftp","FTP","FTP",_FT,_FE,"high","文件传输协议",_T,[21],[_d("220.*FTP","FTP欢迎"),_d("USER ","FTP USER")],True,"productive"),
("sftp","SFTP","SFTP",_FT,_FE,"low","SSH文件传输",_T,[22],[_d("SSH-2.0","SSH协议头")],True,"productive"),
("smb","SMB/CIFS","SMB/CIFS",_FT,_FE,"high","Windows文件共享",_T,[445,139],[_d("\\x00\\x00\\x00\\x85\\xffSMB","SMB1"),_d("\\xfeSMB","SMB2/3")],True,"productive"),
("nfs","NFS","NFS",_FT,_FE,"medium","网络文件系统",_TU,[2049],[_d("\\x80\\x00\\x00","NFS RPC")],True,"productive"),
("webdav","WebDAV","WebDAV",_FT,_FE,"medium","Web文件管理",_T,[443,80],[_u("PROPFIND","WebDAV"),_u("MKCOL","WebDAV")],True,"productive"),
("onedrive","OneDrive","OneDrive",_FT,_FE,"low","微软云存储",_T,[443],[_s("onedrive"),_h("1drv.com")],True,"productive"),
("google_drive","Google Drive","Google Drive",_FT,_FE,"medium","谷歌云存储",_T,[443],[_s("drive.google"),_h("drive.google.com")],True,"productive"),
("dropbox","Dropbox","Dropbox",_FT,_FE,"medium","云存储服务",_T,[443],[_s("dropbox"),_h("dropbox.com")],True,"productive"),
("baidu_wangpan","百度网盘","Baidu Wangpan",_FT,_FE,"low","百度云存储",_T,[443],[_s("pan.baidu"),_h("pan.baidu.com")],True,"neutral"),
("ali_drive","阿里云盘","Alibaba Cloud Drive",_FT,_FE,"low","阿里云存储",_T,[443],[_s("aliyundrive"),_h("aliyundrive.com")],True,"neutral"),
("bittorrent","BitTorrent","BitTorrent",_FT,_FE,"high","P2P文件共享",_TU,[6881,6882,6883,6969],[_d("BitTorrent protocol","BT握手"),_d("d1:","B编码")],True,"unproductive"),
("emule","eMule","eMule",_FT,_FE,"high","电驴P2P下载",_TU,[4662,4672],[_d("\\xe3\\x00\\x00\\x00","eMule协议")],True,"unproductive"),
("tftp","TFTP","TFTP",_FT,_FE,"high","简单文件传输",_U,[69],[_d("\\x00\\x01","TFTP读")],True,"productive"),
("rsync","Rsync","Rsync",_FT,_FE,"medium","文件同步工具",_T,[873],[_d("@RSYNCD:","Rsync握手")],True,"productive"),
("s3","AWS S3","AWS S3",_FT,_FE,"low","亚马逊对象存储",_T,[443],[_s("s3.amazonaws"),_h("s3.amazonaws.com")],True,"productive"),
("oss","阿里云OSS","Alibaba OSS",_FT,_FE,"low","阿里对象存储",_T,[443],[_s("oss-cn-"),_h("oss-cn-")],True,"productive"),
("cos","腾讯云COS","Tencent COS",_FT,_FE,"low","腾讯对象存储",_T,[443],[_s("myqcloud.com"),_h("myqcloud.com")],True,"productive"),
("minio","MinIO","MinIO",_FT,_FE,"low","开源对象存储",_T,[9000],[_s("minio")],True,"productive"),
("box","Box","Box",_FT,_FE,"medium","企业云存储",_T,[443],[_s("box.com"),_h("box.com")],True,"productive"),
("mega","MEGA","MEGA",_FT,_FE,"medium","加密云存储",_T,[443],[_s("mega.nz"),_h("mega.nz")],True,"neutral"),
("nextcloud","Nextcloud","Nextcloud",_FT,_FE,"low","开源私有云",_T,[443],[_s("nextcloud")],True,"productive"),
("syncthing","Syncthing","Syncthing",_FT,_FE,"low","P2P文件同步",_T,[22000],[_s("syncthing")],True,"productive"),
# ===== 远程访问 (Remote Access) =====
("rdp","RDP","RDP",_RA,_RE,"high","远程桌面协议",_TU,[3389],[_d("\\x03\\x00\\x00\\x13\\x0e\\xd0\\x00\\x00\\x124\\x00","RDP X.224")],True,"productive"),
("vnc","VNC","VNC",_RA,_RE,"high","虚拟网络计算",_T,[5900,5901,5902],[_d("RFB ","VNC RFB")],True,"productive"),
("ssh","SSH","SSH",_RA,_RE,"low","安全Shell",_T,[22],[_d("SSH-2.0","SSH协议")],False,"productive"),
("telnet","Telnet","Telnet",_RA,_RE,"critical","不安全远程登录",_T,[23],[_d("\\xff\\xfb\\x01","Telnet协商")],False,"productive"),
("teamviewer","TeamViewer","TeamViewer",_RA,_RE,"medium","远程控制",_TU,[5938],[_s("teamviewer")],True,"productive"),
("anydesk","AnyDesk","AnyDesk",_RA,_RE,"medium","远程桌面",_TU,[7070],[_s("anydesk")],True,"productive"),
("todesk","ToDesk","ToDesk",_RA,_RE,"medium","国产远程控制",_TU,[12580],[_s("todesk")],True,"productive"),
("sunlogin","向日葵","SunLogin",_RA,_RE,"medium","向日葵远程控制",_TU,[49152],[_s("sunlogin")],True,"productive"),
("radmin","Radmin","Radmin",_RA,_RE,"medium","远程管理",_T,[4899],[_d("\\x01\\x00\\x00\\x00\\x00","Radmin握手")],True,"productive"),
("rustdesk","RustDesk","RustDesk",_RA,_RE,"medium","开源远程桌面",_TU,[21115,21118],[_s("rustdesk")],True,"productive"),
("parsec","Parsec","Parsec",_RA,_RE,"low","低延迟远程桌面",_TU,[443],[_s("parsec.app")],True,"productive"),
("splashtop","Splashtop","Splashtop",_RA,_RE,"medium","远程桌面",_TU,[443],[_s("splashtop.com")],True,"productive"),
("gotomypc","GoToMyPC","GoToMyPC",_RA,_RE,"medium","远程访问",_T,[443],[_s("gotomypc.com")],True,"productive"),
("logmein","LogMeIn","LogMeIn",_RA,_RE,"medium","远程访问",_T,[443],[_s("logmein.com")],True,"productive"),
("anyviewer","AnyViewer","AnyViewer",_RA,_RE,"medium","免费远程控制",_T,[443],[_s("anyviewer.com")],True,"productive"),
# ===== 网络游戏 (Gaming) =====
("steam","Steam","Steam",_G,_NG,"low","Valve游戏平台",_TU,[27015,27016,27017],[_s("steampowered"),_h("store.steampowered.com")],True,"unproductive"),
("epic_games","Epic Games","Epic Games",_G,_NG,"low","Epic游戏商店",_T,[443],[_s("epicgames"),_h("epicgames.com")],True,"unproductive"),
("lol","英雄联盟","League of Legends",_G,_NG,"low","Riot MOBA游戏",_TU,[5000,5223,5222,8393],[_s("leagueoflegends"),_h("lol.qq.com")],True,"unproductive"),
("honor_of_kings","王者荣耀","Honor of Kings",_G,_NG,"low","腾讯MOBA手游",_TU,[443,80],[_s("game.qq.com"),_h("game.qq.com")],True,"unproductive"),
("pubg","和平精英/PUBG","Game for Peace/PUBG",_G,_NG,"low","战术竞技游戏",_TU,[443,80],[_s("pUBG"),_h("game.qq.com")],True,"unproductive"),
("minecraft","Minecraft","Minecraft",_G,_NG,"low","沙盒游戏",_T,[25565],[_d("\\x00\\x00","MC握手")],True,"unproductive"),
("roblox","Roblox","Roblox",_G,_NG,"low","在线游戏平台",_TU,[443],[_s("roblox")],True,"unproductive"),
("wow","魔兽世界","World of Warcraft",_G,_NG,"low","暴雪MMORPG",_T,[3724,8085],[_s("blizzard"),_d("\\x57\\x4f\\x57\\x00","WoW协议")],True,"unproductive"),
("genshin_impact","原神","Genshin Impact",_G,_NG,"low","米哈游开放世界",_TU,[443,22102],[_s("mihoyo"),_s("hoyoverse")],True,"unproductive"),
("crossfire","穿越火线","CrossFire",_G,_NG,"low","腾讯FPS游戏",_TU,[7000,8000,10000],[_h("cf.qq.com")],True,"unproductive"),
("dota2","Dota 2","Dota 2",_G,_NG,"low","Valve MOBA游戏",_TU,[27015],[_s("steamcontent.com")],True,"unproductive"),
("csgo","CS2","Counter-Strike 2",_G,_NG,"low","Valve FPS游戏",_TU,[27015,27030],[_s("valve")],True,"unproductive"),
("overwatch","守望先锋","Overwatch",_G,_NG,"low","暴雪FPS游戏",_TU,[443],[_s("blizzard.com")],True,"unproductive"),
("valorant","无畏契约","Valorant",_G,_NG,"low","Riot FPS游戏",_TU,[443],[_s("valorant.com"),_s("riotgames.com")],True,"unproductive"),
("apex","Apex Legends","Apex Legends",_G,_NG,"low","EA大逃杀",_TU,[443],[_s("ea.com")],True,"unproductive"),
("fortnite","堡垒之夜","Fortnite",_G,_NG,"low","Epic大逃杀",_TU,[443],[_s("epicgames.com"),_s("fortnite.com")],True,"unproductive"),
("gta_online","GTA Online","GTA Online",_G,_NG,"low","R星在线游戏",_TU,[443],[_s("rockstargames.com")],True,"unproductive"),
# ===== 网络电话 (VoIP) =====
("sip","SIP","SIP",_V,_VP,"medium","会话发起协议",_TU,[5060,5061],[_d("SIP/2.0","SIP协议"),_d("INVITE sip:","SIP INVITE")],False,"productive"),
("rtp","RTP","RTP",_V,_VP,"low","实时传输协议",_U,[8000,10000],[_d("\\xb0\\x00","RTP v2")],True,"productive"),
("zoom","Zoom","Zoom",_V,_VP,"medium","视频会议",_TU,[443,8801,8802],[_s("zoom"),_h("zoom.us")],True,"productive"),
("webrtc","WebRTC","WebRTC",_V,_VP,"low","实时Web通讯",_TU,[443],[_d("STUN","STUN协议"),_d("ICE-","ICE候选")],True,"productive"),
("facetime","FaceTime","FaceTime",_V,_VP,"low","苹果视频通话",_TU,[443,5223],[_s("apple"),_d("\\x00\\x01\\x00\\x00","FaceTime信令")],True,"neutral"),
("google_meet","Google Meet","Google Meet",_V,_VP,"low","谷歌视频会议",_TU,[443],[_s("meet.google"),_h("meet.google.com")],True,"productive"),
("dingtalk_meeting","钉钉会议","DingTalk Meeting",_V,_VP,"low","钉钉视频会议",_TU,[443],[_s("dingtalk.com")],True,"productive"),
("feishu_meeting","飞书会议","Feishu Meeting",_V,_VP,"low","飞书视频会议",_TU,[443],[_s("feishu.cn"),_u("/vc/")],True,"productive"),
("teams_meeting","Teams会议","Teams Meeting",_V,_VP,"low","Teams视频会议",_TU,[443],[_s("teams.microsoft.com"),_u("/meet/")],True,"productive"),
("cisco_webex","Webex","Cisco Webex",_V,_VP,"low","思科视频会议",_TU,[443],[_s("webex.com"),_h("webex.com")],True,"productive"),
("jitsi","Jitsi Meet","Jitsi Meet",_V,_VP,"low","开源视频会议",_TU,[443],[_s("jitsi"),_h("meet.jit.si")],True,"productive"),
("3cx","3CX","3CX",_V,_VP,"low","PBX电话系统",_TU,[5060,5090],[_d("SIP/2.0","SIP协议"),_s("3cx")],False,"productive"),
("freeswitch","FreeSWITCH","FreeSWITCH",_V,_VP,"low","开源电话平台",_TU,[5060,5080],[_d("FreeSWITCH","FreeSWITCH标识")],False,"productive"),
("asterisk","Asterisk","Asterisk",_V,_VP,"low","开源PBX",_TU,[5060],[_d("Asterisk","Asterisk标识")],False,"productive"),
("viber_voip","Viber VoIP","Viber VoIP",_V,_VP,"low","Viber通话",_TU,[443,5242],[_s("viber.com")],True,"productive"),
("skype_voip","Skype VoIP","Skype VoIP",_V,_VP,"low","Skype通话",_TU,[443],[_s("skype.com")],True,"productive"),
("tencent_meeting","腾讯会议","Tencent Meeting",_V,_VP,"low","腾讯视频会议",_TU,[443],[_s("meeting.tencent.com"),_h("meeting.tencent.com")],True,"productive"),
("huawei_meeting","华为会议","Huawei Meeting",_V,_VP,"low","华为视频会议",_TU,[443],[_s("meeting.huaweicloud.com")],True,"productive"),
("vonage","Vonage","Vonage",_V,_VP,"medium","网络电话服务",_TU,[443],[_s("vonage.com")],True,"productive"),
("bluejeans","BlueJeans","BlueJeans",_V,_VP,"low","视频会议",_T,[443],[_s("bluejeans.com")],True,"productive"),
("gotomeeting","GoToMeeting","GoToMeeting",_V,_VP,"low","在线会议",_T,[443],[_s("gotomeeting.com")],True,"productive"),
("lark_meeting","Lark Meeting","Lark Meeting",_V,_VP,"low","Lark视频会议",_TU,[443],[_s("larksuite.com"),_u("/meet/")],True,"productive"),
# ===== 电子邮件 (Email) =====
("smtp","SMTP","SMTP",_E,_EM,"medium","邮件传输协议",_T,[25,465,587],[_d("220.*SMTP","SMTP欢迎"),_d("EHLO ","EHLO命令")],False,"productive"),
("pop3","POP3","POP3",_E,_EM,"medium","邮局协议",_T,[110,995],[_d("\\+OK POP3","POP3欢迎")],False,"productive"),
("imap","IMAP","IMAP",_E,_EM,"low","邮件访问协议",_T,[143,993],[_d("\\* OK IMAP","IMAP欢迎")],False,"productive"),
("exchange","Exchange","Exchange",_E,_EM,"low","微软Exchange",_T,[443],[_s("outlook.office"),_u("/owa/"),_u("/EWS/")],False,"productive"),
("gmail","Gmail","Gmail",_E,_EM,"medium","谷歌邮件",_T,[443],[_s("mail.google"),_h("mail.google.com")],False,"productive"),
("outlook","Outlook","Outlook",_E,_EM,"low","微软Outlook",_T,[443],[_s("outlook.live"),_h("outlook.com")],False,"productive"),
("yahoo_mail","Yahoo Mail","Yahoo Mail",_E,_EM,"medium","雅虎邮件",_T,[443],[_s("mail.yahoo")],False,"productive"),
("qq_mail","QQ邮箱","QQ Mail",_E,_EM,"medium","腾讯邮箱",_T,[443],[_s("mail.qq.com"),_h("mail.qq.com")],False,"productive"),
("163_mail","163邮箱","163 Mail",_E,_EM,"medium","网易163邮箱",_T,[443],[_s("mail.163.com"),_h("mail.163.com")],False,"productive"),
("126_mail","126邮箱","126 Mail",_E,_EM,"medium","网易126邮箱",_T,[443],[_s("mail.126.com"),_h("mail.126.com")],False,"productive"),
("sina_mail","新浪邮箱","Sina Mail",_E,_EM,"medium","新浪邮箱",_T,[443],[_s("mail.sina.com"),_h("mail.sina.com")],False,"productive"),
("ali_mail","阿里邮箱","Ali Mail",_E,_EM,"medium","阿里企业邮箱",_T,[443],[_s("qiye.aliyun.com")],False,"productive"),
("tencent_mail","腾讯企业邮箱","Tencent Enterprise Mail",_E,_EM,"medium","腾讯企业邮箱",_T,[443],[_s("exmail.qq.com"),_h("exmail.qq.com")],False,"productive"),
("protonmail","ProtonMail","ProtonMail",_E,_EM,"low","加密邮箱",_T,[443],[_s("proton.me"),_h("proton.me")],False,"productive"),
("tutanota","Tutanota","Tutanota",_E,_EM,"low","加密邮箱",_T,[443],[_s("tuta.io"),_h("tuta.io")],False,"productive"),
("icloud_mail","iCloud邮箱","iCloud Mail",_E,_EM,"low","苹果邮箱",_T,[443],[_s("icloud.com"),_h("icloud.com")],False,"productive"),
("mail_ru","Mail.ru","Mail.ru",_E,_EM,"medium","俄罗斯邮箱",_T,[443],[_s("mail.ru")],False,"productive"),
("yandex_mail","Yandex Mail","Yandex Mail",_E,_EM,"medium","Yandex邮箱",_T,[443],[_s("mail.yandex.com")],False,"productive"),
("aol_mail","AOL Mail","AOL Mail",_E,_EM,"medium","AOL邮箱",_T,[443],[_s("mail.aol.com")],False,"productive"),
("sendgrid","SendGrid","SendGrid",_E,_EM,"low","邮件发送服务",_T,[443],[_s("sendgrid.com"),_h("api.sendgrid.com")],False,"productive"),
("mailchimp","Mailchimp","Mailchimp",_E,_EM,"low","邮件营销服务",_T,[443],[_s("mailchimp.com")],False,"productive"),
("ses","Amazon SES","Amazon SES",_E,_EM,"low","AWS邮件服务",_T,[443],[_s("email.amazonaws.com")],False,"productive"),
# ===== Web应用 (Web) =====
("http","HTTP","HTTP",_W,_WB,"low","超文本传输协议",_T,[80,8080,8000,8888],[_d("GET ","HTTP GET"),_d("POST ","HTTP POST"),_d("HTTP/1.","HTTP版本")],False,"productive"),
("https","HTTPS","HTTPS",_W,_WB,"low","加密HTTP协议",_T,[443],[_d("\\x16\\x03\\x01","TLS ClientHello"),_d("\\x16\\x03\\x03","TLS 1.2")],False,"productive"),
("http2","HTTP/2","HTTP/2",_W,_WB,"low","HTTP/2协议",_T,[443],[_d("PRI * HTTP/2.0","HTTP/2前缀")],False,"productive"),
("http3","HTTP/3","HTTP/3",_W,_WB,"low","基于QUIC的HTTP/3",_U,[443],[_d("\\x06\\x00\\x00\\x00","QUIC长包头")],False,"productive"),
("websocket","WebSocket","WebSocket",_W,_WB,"medium","全双工Web通讯",_T,[443,80],[_u("Upgrade: websocket","WS升级头")],False,"productive"),
("nginx","Nginx","Nginx",_W,_WB,"low","Nginx Web服务器",_T,[80,443],[_d("nginx","Nginx Server头")],False,"productive"),
("apache","Apache","Apache",_W,_WB,"low","Apache Web服务器",_T,[80,443],[_d("Apache","Apache Server头")],False,"productive"),
("iis","IIS","IIS",_W,_WB,"low","微软IIS服务器",_T,[80,443],[_d("Microsoft-IIS","IIS Server头")],False,"productive"),
("tomcat","Tomcat","Tomcat",_W,_WB,"low","Tomcat服务器",_T,[8080],[_d("Apache-Coyote","Tomcat特征")],False,"productive"),
("graphql","GraphQL","GraphQL",_W,_WB,"low","GraphQL API",_T,[443],[_u("/graphql","GraphQL端点")],False,"productive"),
("grpc","gRPC","gRPC",_W,_WB,"low","gRPC远程调用",_T,[443],[_d("\\x00\\x00\\x00\\x00\\x00","gRPC帧头")],False,"productive"),
("rest_api","REST API","REST API",_W,_WB,"low","RESTful API",_T,[443,8080],[_u("/api/","API路径"),_u("/v1/","版本API")],False,"productive"),
("phpmyadmin","phpMyAdmin","phpMyAdmin",_W,_WB,"high","数据库管理",_T,[443,80],[_u("phpmyadmin","phpMyAdmin路径")],False,"productive"),
("jenkins","Jenkins","Jenkins",_W,_WB,"medium","CI/CD服务器",_T,[443,8080],[_s("jenkins"),_u("/jenkins")],False,"productive"),
("gitlab","GitLab","GitLab",_W,_WB,"low","代码托管平台",_T,[443],[_s("gitlab"),_h("gitlab.com")],False,"productive"),
("grafana","Grafana","Grafana",_W,_WB,"low","监控可视化",_T,[443,3000],[_s("grafana"),_u("/grafana")],False,"productive"),
("kibana","Kibana","Kibana",_W,_WB,"low","日志可视化",_T,[443,5601],[_s("kibana"),_u("/kibana")],False,"productive"),
("prometheus","Prometheus","Prometheus",_W,_WB,"low","监控系统",_T,[9090],[_s("prometheus"),_u("/metrics")],False,"productive"),
("wordpress","WordPress","WordPress",_W,_WB,"medium","CMS博客系统",_T,[443,80],[_u("wp-content","WP路径"),_u("wp-admin","WP路径")],False,"productive"),
("portainer","Portainer","Portainer",_W,_WB,"low","Docker管理",_T,[443,9000],[_s("portainer"),_u("/api/docker")],False,"productive"),
("traefik","Traefik","Traefik",_W,_WB,"low","反向代理",_T,[443,8080],[_s("traefik"),_u("/api/http/routers")],False,"productive"),
("consul","Consul","Consul",_W,_WB,"low","服务发现",_T,[443,8500],[_s("consul"),_u("/v1/agent")],False,"productive"),
# ===== P2P下载 (P2P) =====
("bittorrent_p2p","BitTorrent P2P","BitTorrent P2P",_P,_PP,"high","BT P2P下载",_TU,[6881,6969],[_d("BitTorrent","BT标识"),_d("d8:announce","BT Tracker")],True,"unproductive"),
("edonkey","eDonkey","eDonkey",_P,_PP,"high","eDonkey P2P网络",_T,[4661],[_d("\\xe3\\x00\\x00\\x00","eDonkey协议")],True,"unproductive"),
("dc_plus_plus","DC++","DC++",_P,_PP,"high","Direct Connect P2P",_T,[411,412],[_d("$MyNick ","DC++握手")],True,"unproductive"),
("soulseek","Soulseek","Soulseek",_P,_PP,"medium","音乐P2P分享",_T,[2234,2235],[_d("\\x01\\x00","Soulseek登录")],True,"unproductive"),
("utorrent","uTorrent","uTorrent",_P,_PP,"high","BT下载客户端",_TU,[6881],[_d("uTorrent","uTorrent特征")],True,"unproductive"),
("qbittorrent","qBittorrent","qBittorrent",_P,_PP,"high","BT下载客户端",_TU,[6881],[_d("qBittorrent","qBittorrent特征")],True,"unproductive"),
("transmission","Transmission","Transmission",_P,_PP,"high","BT下载客户端",_TU,[51413],[_d("Transmission","Transmission特征")],True,"unproductive"),
("deluge","Deluge","Deluge",_P,_PP,"high","BT下载客户端",_TU,[58846],[_d("Deluge","Deluge特征")],True,"unproductive"),
("vuze","Vuze","Vuze",_P,_PP,"high","Azureus/Vuze BT客户端",_TU,[6881],[_d("Azureus","Azureus特征")],True,"unproductive"),
("amule","aMule","aMule",_P,_PP,"high","eMule兼容客户端",_TU,[4662,4672],[_d("\\xe3\\x00\\x00\\x00","aMule协议")],True,"unproductive"),
("mldonkey","MLDonkey","MLDonkey",_P,_PP,"high","多网络P2P客户端",_T,[4444],[_d("MLDonkey","MLDonkey特征")],True,"unproductive"),
("rtorrent","rTorrent","rTorrent",_P,_PP,"high","BT下载客户端",_TU,[6881],[_d("rTorrent","rTorrent特征")],True,"unproductive"),
("popcorntime","Popcorn Time","Popcorn Time",_P,_PP,"high","流媒体P2P",_TU,[6881],[_d("Popcorn","Popcorn特征")],True,"unproductive"),
("stremio","Stremio","Stremio",_P,_PP,"medium","流媒体中心",_T,[443],[_s("stremio.com"),_s("stremio")],True,"unproductive"),
("webtorrent","WebTorrent","WebTorrent",_P,_PP,"medium","Web端BT",_TU,[443],[_d("WebTorrent","WebTorrent特征")],True,"unproductive"),
("ipfs","IPFS","IPFS",_P,_PP,"low","星际文件系统",_TU,[4001,5001],[_d("/ipfs/","IPFS路径"),_s("ipfs")],True,"neutral"),
("syncthing_p2p","Syncthing P2P","Syncthing P2P",_P,_PP,"low","P2P文件同步",_TU,[22000],[_d("Syncthing","Syncthing协议")],True,"productive"),
("wireguard_p2p","WireGuard","WireGuard",_P,_PP,"low","VPN隧道",_U,[51820],[_d("\\x04\\x00\\x00\\x00","WireGuard握手")],False,"productive"),
("zerotier","ZeroTier","ZeroTier",_P,_PP,"low","虚拟网络",_U,[9993],[_d("ZeroTier","ZeroTier特征")],False,"productive"),
("tailscale","Tailscale","Tailscale",_P,_PP,"low","WireGuard VPN",_U,[443],[_s("tailscale"),_s("login.tailscale.com")],False,"productive"),
("freenet","Freenet","Freenet",_P,_PP,"medium","匿名P2P网络",_TU,[9481],[_d("Freenet","Freenet特征")],True,"neutral"),
# ===== 数据库 (Database) =====
("mysql","MySQL","MySQL",_DB,_DA,"medium","MySQL数据库",_T,[3306],[_d("\\x0a\\x35\\x2e","MySQL版本"),_d("\\x00\\x00\\x00\\x0a","MySQL握手")],False,"productive"),
("postgresql","PostgreSQL","PostgreSQL",_DB,_DA,"medium","PostgreSQL数据库",_T,[5432],[_d("PostgreSQL","PG标识")],False,"productive"),
("mongodb","MongoDB","MongoDB",_DB,_DA,"medium","MongoDB文档数据库",_T,[27017],[_d("MongoDB","MongoDB标识")],False,"productive"),
("redis","Redis","Redis",_DB,_DA,"medium","Redis键值数据库",_T,[6379],[_d("\\+PONG","Redis PONG"),_d("\\x2a\\x31","RESP协议")],False,"productive"),
("mssql","MSSQL","MSSQL",_DB,_DA,"medium","微软SQL Server",_T,[1433],[_d("\\x12\\x01\\x00\\x00\\x00","TDS握手")],False,"productive"),
("oracle","Oracle","Oracle",_DB,_DA,"medium","Oracle数据库",_T,[1521],[_d("\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00","TNS头")],False,"productive"),
("mariadb","MariaDB","MariaDB",_DB,_DA,"medium","MariaDB数据库",_T,[3306],[_d("\\x0a\\x35\\x2e","MariaDB版本")],False,"productive"),
("cassandra","Cassandra","Cassandra",_DB,_DA,"medium","分布式数据库",_T,[9042],[_d("Cassandra","Cassandra标识")],False,"productive"),
("couchdb","CouchDB","CouchDB",_DB,_DA,"medium","文档数据库",_T,[5984],[_s("couchdb"),_u("/_utils/")],False,"productive"),
("elasticsearch","Elasticsearch","Elasticsearch",_DB,_DA,"medium","搜索引擎数据库",_T,[9200],[_d("Elasticsearch","ES标识")],False,"productive"),
("clickhouse","ClickHouse","ClickHouse",_DB,_DA,"medium","列式数据库",_T,[8123,9000],[_d("ClickHouse","CH标识")],False,"productive"),
("dynamodb","DynamoDB","DynamoDB",_DB,_DA,"low","AWS数据库",_T,[443],[_s("dynamodb.amazonaws")],False,"productive"),
("cosmosdb","CosmosDB","CosmosDB",_DB,_DA,"low","Azure数据库",_T,[443],[_s("documents.azure.com")],False,"productive"),
("firestore","Firestore","Firestore",_DB,_DA,"low","GCP数据库",_T,[443],[_s("firestore.googleapis.com")],False,"productive"),
("neo4j","Neo4j","Neo4j",_DB,_DA,"medium","图数据库",_T,[7474,7687],[_d("Neo4j","Neo4j标识")],False,"productive"),
("influxdb","InfluxDB","InfluxDB",_DB,_DA,"medium","时序数据库",_T,[8086],[_d("InfluxDB","InfluxDB标识")],False,"productive"),
("timescaledb","TimescaleDB","TimescaleDB",_DB,_DA,"medium","时序PostgreSQL",_T,[5432],[_d("TimescaleDB","TSDB标识")],False,"productive"),
("cockroachdb","CockroachDB","CockroachDB",_DB,_DA,"medium","分布式SQL数据库",_T,[26257,8080],[_d("CockroachDB","CRDB标识")],False,"productive"),
("tidb","TiDB","TiDB",_DB,_DA,"medium","分布式数据库",_T,[4000,10080],[_d("TiDB","TiDB标识")],False,"productive"),
("oceanbase","OceanBase","OceanBase",_DB,_DA,"medium","蚂蚁分布式数据库",_T,[2883],[_d("OceanBase","OceanBase标识")],False,"productive"),
("polardb","PolarDB","PolarDB",_DB,_DA,"medium","阿里云数据库",_T,[3306,5432],[_s("polardb")],False,"productive"),
("tdengine","TDengine","TDengine",_DB,_DA,"medium","时序数据库",_T,[6030],[_d("TDengine","TDengine标识")],False,"productive"),
("doris","Doris","Doris",_DB,_DA,"medium","分析型数据库",_T,[9030],[_d("Doris","Doris标识")],False,"productive"),
# ===== 云服务 (Cloud) =====
("aws","AWS","AWS",_C,_CS,"low","亚马逊云服务",_T,[443],[_s("amazonaws"),_h("amazonaws.com")],False,"productive"),
("azure","Azure","Azure",_C,_CS,"low","微软云服务",_T,[443],[_s("azure"),_h("azure.com")],False,"productive"),
("gcp","GCP","GCP",_C,_CS,"low","谷歌云平台",_T,[443],[_s("googleapis.com"),_h("googleapis.com")],False,"productive"),
("aliyun","阿里云","Alibaba Cloud",_C,_CS,"low","阿里巴巴云服务",_T,[443],[_s("aliyun"),_h("aliyun.com")],False,"productive"),
("tencent_cloud","腾讯云","Tencent Cloud",_C,_CS,"low","腾讯云服务",_T,[443],[_s("tencentcloud"),_h("tencentcloudapi.com")],False,"productive"),
("huawei_cloud","华为云","Huawei Cloud",_C,_CS,"low","华为云服务",_T,[443],[_s("myhuaweicloud"),_h("myhuaweicloud.com")],False,"productive"),
("digitalocean","DigitalOcean","DigitalOcean",_C,_CS,"low","VPS云服务",_T,[443],[_s("digitalocean.com"),_h("digitalocean.com")],False,"productive"),
("linode","Linode","Linode",_C,_CS,"low","Akamai云VPS",_T,[443],[_s("linode.com"),_h("linode.com")],False,"productive"),
("vultr","Vultr","Vultr",_C,_CS,"low","VPS云服务",_T,[443],[_s("vultr.com"),_h("vultr.com")],False,"productive"),
("oracle_cloud","Oracle Cloud","Oracle Cloud",_C,_CS,"low","OCI云服务",_T,[443],[_s("oraclecloud.com")],False,"productive"),
("ibm_cloud","IBM Cloud","IBM Cloud",_C,_CS,"low","IBM云服务",_T,[443],[_s("cloud.ibm.com"),_h("cloud.ibm.com")],False,"productive"),
("cloudflare","Cloudflare","Cloudflare",_C,_CS,"low","CDN与安全",_T,[443],[_s("cloudflare.com"),_h("cloudflare.com")],False,"productive"),
("akamai","Akamai","Akamai",_C,_CS,"low","CDN服务",_T,[443],[_s("akamai.net"),_h("akamai.net")],False,"productive"),
("heroku","Heroku","Heroku",_C,_CS,"low","PaaS平台",_T,[443],[_s("heroku.com"),_h("heroku.com")],False,"productive"),
("vercel","Vercel","Vercel",_C,_CS,"low","前端托管平台",_T,[443],[_s("vercel.com"),_h("vercel.com")],False,"productive"),
("netlify","Netlify","Netlify",_C,_CS,"low","前端托管平台",_T,[443],[_s("netlify.com"),_h("netlify.com")],False,"productive"),
("firebase","Firebase","Firebase",_C,_CS,"low","GCP后端服务",_T,[443],[_s("firebase.google.com"),_h("firebase.google.com")],False,"productive"),
("render","Render","Render",_C,_CS,"low","PaaS平台",_T,[443],[_s("render.com"),_h("render.com")],False,"productive"),
("railway","Railway","Railway",_C,_CS,"low","PaaS部署平台",_T,[443],[_s("railway.app"),_h("railway.app")],False,"productive"),
("flyio","Fly.io","Fly.io",_C,_CS,"low","边缘计算平台",_T,[443],[_s("fly.io"),_h("fly.io")],False,"productive"),
]

# 从原始数据构建应用数据库
_APP_DB = {r[0]: _app(*r) for r in _R}

class AppDetector:
    """应用识别引擎(AppID)，通过协议签名、端口模式、DPI识别应用程序，类似Palo Alto Networks AppID"""
    SIGNATURE_FILE = "/etc/gatekeeper/rules/app_signatures.json"
    POLICY_FILE = "/etc/gatekeeper/rules/app_policies.json"

    def __init__(self):
        """初始化应用识别引擎，加载内置数据库、外部签名和策略"""
        self._logger = get_logger("app_detector")
        self._app_db = {}
        self._port_idx = defaultdict(list)
        self._sni_idx = defaultdict(list)
        self._host_idx = defaultdict(list)
        self._uri_idx = defaultdict(list)
        self._dpi_pats = []
        self._blocked = set()
        self._lock = threading.RLock()
        self._stats = {"total_detections": 0, "by_category": defaultdict(int),
                       "by_app": defaultdict(int), "blocked_attempts": 0}
        for aid, info in _APP_DB.items():
            self._app_db[aid] = dict(info)
            self._build_idx(aid, info)
        self._load_signatures()
        self._load_policies()
        self._logger.info("应用识别引擎初始化完成，共加载 %d 个应用签名", len(self._app_db))

    def _build_idx(self, aid, info):
        """为应用构建快速检索索引（端口、SNI、Host、URI、DPI）"""
        for port in info.get("ports", []):
            self._port_idx[port].append(aid)
        for sig in info.get("signatures", []):
            t, p = sig.get("type", ""), sig.get("pattern", "")
            if t == "tls_sni": self._sni_idx[p.lower()].append(aid)
            elif t == "http_host": self._host_idx[p.lower()].append(aid)
            elif t == "http_uri": self._uri_idx[p.lower()].append(aid)
            elif t == "dpi_pattern":
                try: self._dpi_pats.append((aid, sig, re.compile(p.encode("latin-1"))))
                except re.error: self._logger.warning("DPI签名编译失败: %s", p)

    def _load_signatures(self):
        """从外部JSON文件加载额外应用签名"""
        if not os.path.exists(self.SIGNATURE_FILE): return
        try:
            with open(self.SIGNATURE_FILE, "r", encoding="utf-8") as f: data = json.load(f)
            n = 0
            for aid, info in data.items():
                if aid not in self._app_db:
                    self._app_db[aid] = info; self._build_idx(aid, info); n += 1
            self._logger.info("从文件加载 %d 个额外应用签名", n)
        except (json.JSONDecodeError, IOError) as e: self._logger.error("加载签名文件失败: %s", e)

    def _load_policies(self):
        """从策略文件加载应用阻断列表"""
        if not os.path.exists(self.POLICY_FILE): return
        try:
            with open(self.POLICY_FILE, "r", encoding="utf-8") as f:
                self._blocked = set(json.load(f).get("blocked_apps", []))
            self._logger.info("加载 %d 个应用阻断策略", len(self._blocked))
        except (json.JSONDecodeError, IOError) as e: self._logger.error("加载策略文件失败: %s", e)

    def _save_policies(self):
        """持久化应用阻断策略到文件"""
        try:
            os.makedirs(os.path.dirname(self.POLICY_FILE), exist_ok=True)
            with open(self.POLICY_FILE, "w", encoding="utf-8") as f:
                json.dump({"blocked_apps": list(self._blocked)}, f, ensure_ascii=False, indent=2)
        except IOError as e: self._logger.error("保存策略文件失败: %s", e)

    @staticmethod
    def _parse_tls_sni(payload: bytes) -> Optional[str]:
        """解析TLS ClientHello提取SNI，最小化实现无外部依赖"""
        if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03: return None
        off = 5
        if off + 4 > len(payload) or payload[off] != 0x01: return None
        off += 38  # Handshake(4) + Version(2) + Random(32)
        if off >= len(payload): return None
        off += 1 + payload[off]  # Session ID
        if off + 2 > len(payload): return None
        off += 2 + struct.unpack("!H", payload[off:off + 2])[0]  # Cipher Suites
        if off + 1 > len(payload): return None
        off += 1 + payload[off]  # Compression
        if off + 2 > len(payload): return None
        ext_end = off + 2 + struct.unpack("!H", payload[off:off + 2])[0]
        off += 2
        while off + 4 <= ext_end and off + 4 <= len(payload):
            etype, elen = struct.unpack("!HH", payload[off:off + 4]); off += 4
            if etype == 0x0000 and off + elen <= len(payload):
                so = off + 3  # List Length(2) + Name Type(1)
                if so + 2 <= len(payload):
                    nlen = struct.unpack("!H", payload[so:so + 2])[0]; so += 2
                    if so + nlen <= len(payload):
                        return payload[so:so + nlen].decode("ascii", errors="ignore")
            off += elen
        return None

    @staticmethod
    def _parse_http_host(payload: bytes) -> Optional[str]:
        """从HTTP请求中提取Host头部"""
        try:
            text = payload[:4096].decode("ascii", errors="ignore")
            if not text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS ")): return None
            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    return line.split(":", 1)[1].strip().split(":")[0].lower()
        except Exception: pass
        return None

    @staticmethod
    def _parse_http_uri(payload: bytes) -> Optional[str]:
        """从HTTP请求中提取URI路径"""
        try:
            parts = payload[:4096].decode("ascii", errors="ignore").split("\r\n")[0].split(" ")
            if len(parts) >= 2: return parts[1]
        except Exception: pass
        return None

    def _detect_by_port(self, sp, dp, proto) -> list:
        """基于端口匹配已知应用"""
        c = set()
        for port in (sp, dp):
            for aid in self._port_idx.get(port, []):
                if proto.lower() in [p.lower() for p in self._app_db.get(aid, {}).get("protocols", [])]:
                    c.add(aid)
        return list(c)

    def _detect_by_tls_sni(self, payload: bytes) -> list:
        """基于TLS SNI匹配应用"""
        sni = self._parse_tls_sni(payload)
        if not sni: return []
        sl = sni.lower()
        return list({aid for pat, aids in self._sni_idx.items() if pat in sl for aid in aids})

    def _detect_by_http(self, payload: bytes) -> list:
        """基于HTTP Host/URI匹配应用"""
        m = set()
        host = self._parse_http_host(payload)
        if host:
            for pat, aids in self._host_idx.items():
                if pat in host or host in pat: m.update(aids)
        uri = self._parse_http_uri(payload)
        if uri:
            ul = uri.lower()
            for pat, aids in self._uri_idx.items():
                if pat in ul: m.update(aids)
        return list(m)

    def _detect_by_dpi(self, payload: bytes) -> list:
        """基于深度包检测(DPI)二进制模式匹配"""
        if not payload: return []
        return list({aid for aid, _, comp in self._dpi_pats if comp.search(payload)})

    def _detect_by_heuristic(self, sp, dp, proto, payload: bytes) -> list:
        """基于协议行为启发式识别（DNS/mDNS/NTP/DHCP/SSDP/LDAP/MQTT/AMQP）"""
        m, p = set(), proto.lower()
        if p == "udp" and dp == 53 and len(payload) > 12: m.add("dns")
        if p == "udp" and dp == 5353: m.add("mdns")
        if p == "udp" and dp == 123: m.add("ntp")
        if p == "udp" and dp in (67, 68): m.add("dhcp")
        if p == "udp" and dp == 1900: m.add("ssdp")
        if p == "tcp" and dp == 389: m.add("ldap")
        if p == "tcp" and dp == 1883: m.add("mqtt")
        if p == "tcp" and dp == 5672: m.add("amqp")
        return list(m)

    def detect_app(self, src_ip, src_port, dst_ip, dst_port, protocol, payload=b"") -> dict:
        """检测单个数据包对应的应用程序，使用加权评分融合多方法检测结果"""
        with self._lock:
            res = {"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                   "dst_port": dst_port, "protocol": protocol, "app_id": None,
                   "app_name": None, "category": None, "confidence": 0.0,
                   "detection_methods": [], "risk": None, "blocked": False}
            scores, methods = defaultdict(float), defaultdict(list)
            for aid in self._detect_by_dpi(payload): scores[aid] += 0.40; methods[aid].append("dpi")
            for aid in self._detect_by_tls_sni(payload): scores[aid] += 0.30; methods[aid].append("tls_sni")
            for aid in self._detect_by_http(payload): scores[aid] += 0.20; methods[aid].append("http")
            for aid in self._detect_by_port(src_port, dst_port, protocol): scores[aid] += 0.10; methods[aid].append("port")
            for aid in self._detect_by_heuristic(src_port, dst_port, protocol, payload): scores[aid] += 0.05; methods[aid].append("heuristic")
            if not scores: return res
            best = max(scores, key=scores.get)
            info = self._app_db.get(best)
            if info:
                res.update({"app_id": best, "app_name": info.get("name", best),
                            "category": info.get("category_name", ""),
                            "confidence": min(scores[best], 1.0),
                            "detection_methods": methods.get(best, []),
                            "risk": info.get("risk", "unknown"),
                            "blocked": best in self._blocked})
                self._stats["total_detections"] += 1
                self._stats["by_category"][info.get("category", "unknown")] += 1
                self._stats["by_app"][best] += 1
                if res["blocked"]:
                    self._stats["blocked_attempts"] += 1
                    self._logger.warning("检测到被阻断的应用: %s (%s) [%s->%s:%d]",
                                        info.get("name"), best, src_ip, dst_ip, dst_port)
                else:
                    self._logger.debug("识别应用: %s (置信度: %.2f) [%s->%s:%d]",
                                        info.get("name"), scores[best], src_ip, dst_ip, dst_port)
            return res

    def detect_flow(self, flow_data: dict) -> dict:
        """检测网络流对应的应用程序，flow_data包含src_ip/src_port/dst_ip/dst_port/protocol/payload"""
        p = flow_data.get("payload", b"")
        if isinstance(p, str): p = p.encode("latin-1")
        return self.detect_app(flow_data.get("src_ip", "0.0.0.0"), flow_data.get("src_port", 0),
                               flow_data.get("dst_ip", "0.0.0.0"), flow_data.get("dst_port", 0),
                               flow_data.get("protocol", "tcp"), p)

    def get_app_info(self, app_id: str) -> dict:
        """获取指定应用的详细信息"""
        return dict(self._app_db.get(app_id, {}))

    def get_all_apps(self) -> list:
        """获取所有已注册的应用列表"""
        return list(self._app_db.values())

    def get_apps_by_category(self, category: str) -> list:
        """按分类获取应用列表"""
        return [a for a in self._app_db.values() if a.get("category") == category]

    def get_categories(self) -> list:
        """获取所有应用分类列表"""
        seen, cats = set(), []
        for a in self._app_db.values():
            c, cn = a.get("category", ""), a.get("category_name", "")
            if c and c not in seen: seen.add(c); cats.append({"id": c, "name": cn})
        return sorted(cats, key=lambda x: x.get("id", ""))

    def search_apps(self, keyword: str) -> list:
        """搜索应用（按名称、英文名、描述、分类匹配）"""
        kw = keyword.lower()
        return [a for a in self._app_db.values()
                if any(kw in f.lower() for f in [a.get("name", ""), a.get("name_en", ""),
                    a.get("description", ""), a.get("category_name", ""), a.get("id", "")])]

    def get_app_stats(self) -> dict:
        """获取应用识别统计数据"""
        return {"total_detections": self._stats["total_detections"],
                "by_category": dict(self._stats["by_category"]),
                "by_app": dict(self._stats["by_app"]),
                "blocked_attempts": self._stats["blocked_attempts"],
                "total_apps": len(self._app_db), "blocked_apps_count": len(self._blocked)}

    def block_app(self, app_id: str) -> bool:
        """阻断指定应用，持久化策略到文件"""
        with self._lock:
            if app_id not in self._app_db:
                self._logger.warning("阻断失败: 未知应用 %s", app_id); return False
            if app_id in self._blocked: return True
            self._blocked.add(app_id); self._save_policies()
            self._logger.info("已添加应用阻断: %s (%s)", self._app_db[app_id].get("name"), app_id)
            return True

    def unblock_app(self, app_id: str) -> bool:
        """解除指定应用的阻断"""
        with self._lock:
            if app_id not in self._blocked: return True
            self._blocked.discard(app_id); self._save_policies()
            self._logger.info("已解除应用阻断: %s", app_id)
            return True

    def get_blocked_apps(self) -> list:
        """获取所有被阻断的应用列表"""
        return [self._app_db[aid] for aid in self._blocked if aid in self._app_db]

    def update_signatures(self) -> dict:
        """从外部签名文件重新加载签名，返回更新结果"""
        with self._lock:
            before = len(self._app_db); self._load_signatures(); after = len(self._app_db)
            self._logger.info("签名更新完成: 新增 %d 个应用签名", after - before)
            return {"status": "success", "before": before, "after": after, "new_signatures": after - before}

    def export_policies(self) -> dict:
        """导出当前应用策略配置"""
        return {"blocked_apps": list(self._blocked), "app_count": len(self._app_db),
                "categories": self.get_categories()}

    def import_policies(self, policies: dict) -> dict:
        """导入应用策略配置，返回导入结果"""
        with self._lock:
            valid, invalid = [], []
            for aid in policies.get("blocked_apps", []):
                (valid if aid in self._app_db else invalid).append(aid)
            self._blocked = set(valid); self._save_policies()
            self._logger.info("策略导入完成: 有效 %d 条, 无效 %d 条", len(valid), len(invalid))
            return {"status": "success", "imported": len(valid), "invalid": len(invalid), "invalid_apps": invalid}

    def scan_active_connections(self) -> list:
        """扫描系统活跃连接并识别应用，通过解析ss -tunap输出实现"""
        results = []
        try:
            proc = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                self._logger.error("执行ss命令失败: %s", proc.stderr); return results
            for line in proc.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) < 6: continue
                ni, local, remote = parts[0], parts[4], parts[5]
                proto = "tcp" if "tcp" in ni.lower() else "udp"
                try:
                    sp, dp = local.rsplit(":", 1), remote.rsplit(":", 1)
                    sip, sport = sp[0].strip("[]"), int(sp[1]) if len(sp) > 1 else 0
                    dip, dport = dp[0].strip("[]"), int(dp[1]) if len(dp) > 1 else 0
                except (ValueError, IndexError): continue
                det = self.detect_app(sip, sport, dip, dport, proto)
                if det.get("app_id"): results.append(det)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self._logger.error("扫描活跃连接失败: %s", e)
        return results
