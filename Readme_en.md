# Other Resource Collection Projects:
- [All open source security tools I collected: sec-tool-list](https://github.com/alphaSeclab/sec-tool-list/blob/master/Readme_en.md): More than 18K. Both Markdown and Json format.
- [Reverse Engineering Resources: awesome-reverse-engineering](https://github.com/alphaSeclab/awesome-reverse-engineering/blob/master/Readme_en.md): IDA/Ghidra/x64dbg/OllDbg/WinDBG/CuckooSandbox/Radare2/BinaryNinja/DynamoRIO/IntelPin/Frida/Qemu/AndroidSecurity/iOSSecurity/WindowSecurity/LinuxSecurity/GameHacking/Bootkit/Rootkit/Angr/Shellcode/ProcessInjection/CodeInjection/DLLInjection/WSL/Sysmon/...
- [Network Related Resources: awesome-network-stuff](https://github.com/alphaSeclab/awesome-network-stuff/blob/master/Readme_en.md): Proxy/GFW/ReverseProxy/Tunnel/VPN/Tor/I2P, and MiTM/PortKnocking/NetworkSniff/NetworkAnalysis/etc
- [Offensive Security Resources: awesome-cyber-security](https://github.com/alphaSeclab/awesome-cyber-security/blob/master/Readme_en.md): Vulnerability/Pentest/IoTSecurity/DataExfiltration/Metasploit/BurpSuite/KaliLinux/C&C/OWASP/AntiVirus/CobaltStrike/Recon/OSINT/SocialEnginneringAttack/Password/Credential/ThreatHunting/Payload/WifiHacking/PostExploitation/PrivilegeEscalation/UACBypass/...
- [open source RAT and malicious RAT analysis reports: awesome-rat](https://github.com/alphaSeclab/awesome-rat/blob/master/Readme_en.md): RAT for all platforms: Windows/Linux/macOS/Android; malicious RAT analysis reports
- [Webshell Resource Collection: awesome-webshell](https://github.com/alphaSeclab/awesome-webshell/blob/master/Readme_en.md): Almost 150 open source tools, and 200 blog posts about webhsell.
- [Forensics Resource Collection: awesome-forensics](https://github.com/alphaSeclab/awesome-forensics/blob/master/Readme_en.md): Almost 300 open source forensics tools, and 600 blog posts about forensics.




# Forensics


# Directory
- [Tools](#d4e014cbc478d3e5625e6ca1622781d3)
    - [(157) Recent Add](#ecb63dfb62722feb6d43a9506515b4e3)
    - [(3) LinuxDistro](#bd653a0f2c8ff4aab78bb2be2257362b)
    - [(9) Resource Collection](#601dcc03dc2254612e1b88816ae2b820)
    - [(74) Volatility](#4d2a33083a894d6e6ef01b360929f30a)
    - [(5) sleuthkit](#8159418f807637a0d70406803a3c08c5)
    - [(4) Rekall](#0b1db12ec509cd6fb489c93a4cc837d5)
    - [(3) bulk_extractor](#0d23b542d7b0b1069a91f6c500009c3a)
    - [(9) Anti-Forensic](#bd015dd7245b420dca75a267133ddce3)
    - [(7) macOS](#9c0413531a5b5afd12b89ccdc744afbd)
    - [(2) iOS](#a93df189246db405e8182a42d3f7e553)
    - [(8) Linux](#505d67a56d03c921dd19737c28c3d8fc)
- [Forensics](#c81ed9f7fec66ce81b864962ed4ea9c7)
    - [(399) Recent Add](#fbccbf27fb92d876bdfb1626e4e0e86c)
    - [(150) Volatility](#bc6550163d1995f3ce6323404e2cec28)
    - [(4) Sleuthkit](#c529f60a5b6f420255ae79843446a145)
    - [(13) Rekall](#b6797fda3a16667cd5726ef4aa86b0e1)


# <a id="c81ed9f7fec66ce81b864962ed4ea9c7"></a>Forensics


***


## <a id="fbccbf27fb92d876bdfb1626e4e0e86c"></a>Recent Add


- 2019.12 [sans] [HSTS For Forensics: You Can Run, But You Can't Use HTTP](https://digital-forensics.sans.org/blog/2019/12/17/hsts-for-forensics-you-can-run-but-you-cant-use-http)
- 2019.12 [eforensicsmag] [6 Threat Intelligence Sources That Will Help Enhance Digital Forensics Readiness | By Jonathan Zhang](https://eforensicsmag.com/6-threat-intelligence-sources-that-will-help-enhance-digital-forensics-readiness-by-jonathan-zhang/)
- 2019.12 [mac4n6] [New(ish) Presentation: Poking the Bear - Teasing out Apple's Secrets through Dynamic Forensic Testing and Analysis](https://www.mac4n6.com/blog/2019/12/10/newish-presentation-poking-the-bear-teasing-out-apples-secrets-through-dynamic-forensic-testing-and-analysis)
- 2019.12 [4hou] [移动设备数字取证过程概述（下）](https://www.4hou.com/tools/22000.html)
- 2019.12 [4hou] [移动设备数字取证过程概述（上）](https://www.4hou.com/system/21685.html)
- 2019.11 [freebuf] [DFIRTriage：针对Windows的事件应急响应数字取证工具](https://www.freebuf.com/articles/system/220240.html)
- 2019.11 [freebuf] [Windows系统安全事件日志取证工具：LogonTracer](https://www.freebuf.com/sectool/219786.html)
- 2019.11 [compass] [Challenging Your Forensic Readiness with an Application-Level Ransomware Attack](https://blog.compass-security.com/2019/11/challenging-your-forensic-readiness-with-an-application-level-ransomware-attack/)
- 2019.11 [freebuf] [AutoMacTC：一款针对macOS环境的自动化取证分类采集器](https://www.freebuf.com/sectool/218812.html)
- 2019.11 [eforensicsmag] [CRYPTO & DATA ERASURE: After forensic analysis drives should be securely wiped | By Paul Katzoff](https://eforensicsmag.com/crypto-data-erasure-after-forensic-analysis-drives-should-be-securely-wiped-by-paul-katzoff/)
- 2019.10 [eforensicsmag] [Encrypted file system forensics - Introduction (EXT4) [FREE COURSE CONTENT]](https://eforensicsmag.com/encrypted-file-system-forensics-introduction-ext4/)
- 2019.10 [4hou] [iPhone取证的通用方法](https://www.4hou.com/web/21192.html)
- 2019.10 [Cooper] [Beyond Windows Forensics With Built-in Microsoft Tooling - Thomas Fischer](https://www.youtube.com/watch?v=_hSuoNAfOSE)
- 2019.10 [Cooper] [Memory Forensics Analysis Of Cisco IOS XR 32 Bits Routers With 'Amnesic-Sherpa' - Solal Jacob](https://www.youtube.com/watch?v=ukZnBh6r8Q8)
- 2019.10 [4hou] [如何在Windows上重现macOS上的取证技巧](https://www.4hou.com/web/20530.html)
- 2019.10 [HackersOnBoard] [Lessons from Virginia - A Comparative Forensic Analysis of WinVote Voting Machine](https://www.youtube.com/watch?v=1z7z853__5E)
- 2019.10 [HackersOnBoard] [Black Hat USA 2016 Memory Forensics Using Virtual Machine Introspection for Cloud Computing](https://www.youtube.com/watch?v=NNbiZD15NFA)
- 2019.10 [elcomsoft] [Installing and using iOS Forensic Toolkit on macOS 10.15 Catalina](https://blog.elcomsoft.com/2019/10/installing-and-using-ios-forensic-toolkit-on-macos-catalina/)
- 2019.09 [mac4n6] [Just Call Me Buffy the Proto Slayer – An Initial Look into Protobuf Data in Mac and iOS Forensics](https://www.mac4n6.com/blog/2019/9/27/just-call-me-buffy-the-proto-slayer-an-initial-look-into-protobuf-data-in-mac-and-ios-forensics)
- 2019.09 [venus] [RDP 登录日志取证与清除](https://paper.seebug.org/1043/)
- 2019.09 [freebuf] [Usbrip：用于跟踪USB设备固件的简单CLI取证工具](https://www.freebuf.com/sectool/210305.html)
- 2019.09 [PositiveTechnologies] [Forensics: why there are no perfect crimes](https://www.youtube.com/watch?v=NgjUi7dSEsg)
- 2019.09 [sans] [Strengthen Your Investigatory Powers by Taking the New FOR498: Battlefield Forensics & Data Acquisition Course from SANS](https://digital-forensics.sans.org/blog/2019/09/16/strengthen-your-investigatory-powers-for498)
- 2019.09 [4hou] [什么是数字取证(Digital forensics)？ 如何在这个热门领域站稳脚跟？](https://www.4hou.com/info/news/20249.html)
- 2019.09 [4hou] [使用osquery进行远程取证](https://www.4hou.com/web/18369.html)
- 2019.09 [elcomsoft] [Apple TV Forensics 03: Analysis](https://blog.elcomsoft.com/2019/09/apple-tv-forensics-03-analysis/)
- 2019.09 [securelayer7] [CAN Bus protocol Penetration testing and forensics](https://blog.securelayer7.net/can-bus-protocol-penetration-testing-and-forensics/)
- 2019.09 [hackers] [Network Forensics, Part 3: tcpdump for Network Analysis](https://www.hackers-arise.com/single-post/2019/09/03/Network-Forensics-Part-3-tcpdump-for-Network-Analysis)
- 2019.09 [freebuf] [浅谈电子数字取证技术](https://www.freebuf.com/articles/network/211643.html)
- 2019.09 [diablohorn] [Notes on ZFS / Solaris forensics](https://diablohorn.com/2019/09/01/notes-on-zfs-solaris-forensics/)
- 2019.08 [THER] [[tool] Network Forensics with Tshark](https://www.youtube.com/watch?v=BETB___XKs0)
- 2019.08 [elcomsoft] [Passcode vs. Biometrics: Forensic Implications of Touch ID and Face ID in iOS 12](https://blog.elcomsoft.com/2019/08/passcode-vs-biometrics-forensic-implications-of-touch-id-and-face-id-in-ios-12/)
- 2019.08 [hackers] [Digital Forensics, Part 11: Recovering Stored Passwords from the Browser](https://www.hackers-arise.com/single-post/2019/08/27/Digital-Forensics-Part-11-Recovering-Stored-Passwords-from-the-Browser)
- 2019.08 [freebuf] [MIG：一款功能强大的高速分布式实时数据取证工具](https://www.freebuf.com/sectool/208933.html)
- 2019.08 [freebuf] [用于监控USB设备连接事件的取证工具](https://www.freebuf.com/sectool/210862.html)
- 2019.08 [0x00sec] [CAN-bus protocol pentesting and forensics](https://0x00sec.org/t/can-bus-protocol-pentesting-and-forensics/15689)
- 2019.08 [4hou] [有没有想过一个问题，适用于移动设备的取证方法能否照搬到台式计算机上？](https://www.4hou.com/web/19641.html)
- 2019.08 [mac4n6] [New Presentation from SANS DFIR Summit 2019 - They See Us Rollin', They Hatin' - Forensics of iOS CarPlay and Android Auto](https://www.mac4n6.com/blog/2019/8/6/new-presentation-from-sans-dfir-summit-2019-they-see-us-rollin-they-hatin-forensics-of-ios-carplay-and-android-auto)
- 2019.08 [X13Cubed] [NTFS Journal Forensics](https://www.youtube.com/watch?v=1mwiShxREm8)
- 2019.08 [MastersInEthicalHacking] [Computer Forensic Tutorials || Install Dumpzilla on Kali Linux](https://www.youtube.com/watch?v=fc8oZcTtidw)
- 2019.07 [elcomsoft] [Extended Mobile Forensics: Analyzing Desktop Computers](https://blog.elcomsoft.com/2019/07/extended-mobile-forensics-analyzing-desktop-computers/)
- 2019.07 [eforensicsmag] [Mounting forensic images using losetup cli [FREE COURSE CONTENT]](https://eforensicsmag.com/mounting-forensic-images-using-losetup-cli-free-course-content/)
- 2019.07 [elcomsoft] [iOS 13 (Beta) Forensics](https://blog.elcomsoft.com/2019/07/ios-13-beta-forensics/)
- 2019.07 [infosecinstitute] [Getting started in digital forensics](https://resources.infosecinstitute.com/podcast-getting-started-in-digital-forensics/)
- 2019.07 [4hou] [iOS越狱和物理取证指南](https://www.4hou.com/reverse/18468.html)
- 2019.07 [4hou] [对Apple Watch的取证分析（续）](https://www.4hou.com/web/18879.html)
- 2019.07 [eforensicsmag] [Case Study: Extracting And Analyzing Messenger Data With Oxygen Forensic Detective | By Nikola Novak](https://eforensicsmag.com/case-study-extracting-and-analyzing-messenger-data-with-oxygen-forensic-detective-by-nikola-novak/)
- 2019.07 [andreafortuna] [How to convert a Windows SFS (Dynamic Disks) partition to regular partition for forensic analysis](https://www.andreafortuna.org/2019/07/04/how-to-convert-a-windows-sfs-dynamic-disks-partition-to-regular-partition-for-forensic-analysis/)
- 2019.07 [4hou] [Apple TV和Apple Watch的取证分析](https://www.4hou.com/web/18830.html)
- 2019.07 [arxiv] [[1907.01421] Methodology for the Automated Metadata-Based Classification of Incriminating Digital Forensic Artefacts](https://arxiv.org/abs/1907.01421)
- 2019.06 [arxiv] [[1907.00074] Forensic Analysis of Third Party Location Applications in Android and iOS](https://arxiv.org/abs/1907.00074)
- 2019.06 [elcomsoft] [Apple Watch Forensics 02: Analysis](https://blog.elcomsoft.com/2019/06/apple-watch-forensics-02-analysis/)
- 2019.06 [hackers] [Network Forensics, Part 2: Packet-Level Analysis of the NSA's  EternalBlue Exploit](https://www.hackers-arise.com/single-post/2018/11/30/Network-Forensics-Part-2-Packet-Level-Analysis-of-the-EternalBlue-Exploit)
- 2019.06 [elcomsoft] [Apple TV and Apple Watch Forensics 01: Acquisition](https://blog.elcomsoft.com/2019/06/apple-tv-and-apple-watch-forensics-01-acquisition/)
- 2019.06 [eforensicsmag] [Forensic Analysis of OpenVPN on iOS | By Jack Farley](https://eforensicsmag.com/forensic-analysis-of-openvpn-on-ios-by-jack-farley/)
- 2019.06 [mac4n6] [New Presentation from MacDevOpsYVR 2019 - Launching APOLLO: Creating a Simple Tool for Advanced Forensic Analysis](https://www.mac4n6.com/blog/2019/6/17/new-presentation-from-macdevopsyvr-2019-launching-apollo-creating-a-simple-tool-for-advanced-forensic-analysis)
- 2019.06 [eforensicsmag] [Forensic Acquisitions over Netcat | By Ali Hadi](https://eforensicsmag.com/forensic-acquisitions-over-netcat-by-ali-hadi/)
- 2019.06 [arxiv] [[1906.10625] Antiforensic techniques deployed by custom developed malware in evading anti-virus detection](https://arxiv.org/abs/1906.10625)
- 2019.06 [h2hconference] [Memory anti-anti-forensics in a nutshell - Fuschini & Rodrigues - H2HC 2013](https://www.youtube.com/watch?v=BdSwrhyjfMA)
- 2019.06 [elcomsoft] [Forensic Implications of iOS Jailbreaking](https://blog.elcomsoft.com/2019/06/forensic-implications-of-ios-jailbreaking/)
- 2019.06 [arxiv] [[1906.05268] Differential Imaging Forensics](https://arxiv.org/abs/1906.05268)
- 2019.06 [eforensicsmag] [My Digital Forensic Career Pathway | By Patrick Doody](https://eforensicsmag.com/my-digital-forensic-career-pathway-by-patrick-doody/)
- 2019.05 [trailofbits] [Using osquery for remote forensics](https://blog.trailofbits.com/2019/05/31/using-osquery-for-remote-forensics/)
- 2019.05 [freebuf] [CyberScan：用于数据包取证的渗透工具](https://www.freebuf.com/sectool/203306.html)
- 2019.05 [HackEXPlorer] [Digital Photo Forensics: How To analyze Fake Photos](https://www.youtube.com/watch?v=G1Y0UTMTF7o)
- 2019.05 [eforensicsmag] ["Most people neglect scrutinizing the basics" - Interview with Divya Lakshmanan, eForensics Instructor](https://eforensicsmag.com/most-people-neglect-scrutinizing-the-basics-interview-with-divya-lakshmanan-eforensics-instructor/)
- 2019.05 [andreafortuna] [How to read Windows Hibernation file (hiberfil.sys) to extract forensic data?](https://www.andreafortuna.org/2019/05/15/how-to-read-windows-hibernation-file-hiberfil-sys-to-extract-forensic-data/)
- 2019.05 [MastersInEthicalHacking] [Computer Memory Forensic Tutorial](https://www.youtube.com/watch?v=H_FL4n84LI0)
- 2019.05 [360] [2019 虎鲸杯电子取证大赛赛后复盘总结](https://www.anquanke.com/post/id/177714/)
- 2019.05 [eforensicsmag] [BLAZESCAN – digital forensic open source tool | By Brian Laskowski](https://eforensicsmag.com/blazescan-digital-forensic-open-source-tool-by-brian-laskowski/)
- 2019.04 [X13Cubed] [Free Tools From Magnet Forensics](https://www.youtube.com/watch?v=nTaYglAhbTU)
- 2019.04 [4hou] [利用LeechAgent对远程物理内存进行取证分析](https://www.4hou.com/technology/17336.html)
- 2019.04 [freebuf] [Imago-Forensics：Python实现的图像数字取证工具](https://www.freebuf.com/sectool/200845.html)
- 2019.04 [andreafortuna] [How to extract forensic artifacts from pagefile.sys?](https://www.andreafortuna.org/2019/04/17/how-to-extract-forensic-artifacts-from-pagefile-sys/)
- 2019.04 [scrtinsomnihack] [Dear Blue Team: Forensics Advice to Supercharge your DFIR capabilities by Joe Gray (@c_3pjoe)](https://www.youtube.com/watch?v=HEsCSba92XA)
- 2019.04 [eforensicsmag] [Instagram Forensics -Windows App Store | By Justin Boncaldo](https://eforensicsmag.com/instagram-forensics-windows-app-store-by-justin-boncaldo/)
- 2019.04 [arxiv] [[1904.01725] Using Google Analytics to Support Cybersecurity Forensics](https://arxiv.org/abs/1904.01725)
- 2019.03 [aliyun] [Compromised Server--取证挑战](https://xz.aliyun.com/t/4523)
- 2019.03 [4hou] [Windows注册表取证分析](https://www.4hou.com/info/news/15731.html)
- 2019.03 [arxiv] [[1903.10770] Blockchain Solutions for Forensic Evidence Preservation in IoT Environments](https://arxiv.org/abs/1903.10770)
- 2019.03 [compass] [Windows Forensics with Plaso](https://blog.compass-security.com/2019/03/windows-forensics-with-plaso/)
- 2019.03 [checkpoint] [Check Point Forensic Files: A New Monero CryptoMiner Campaign | Check Point Software Blog](https://blog.checkpoint.com/2019/03/19/check-point-forensic-files-monero-cryptominer-campaign-cryptojacking-crypto-apt-hacking/)
- 2019.03 [arxiv] [[1903.07703] A Survey of Electromagnetic Side-Channel Attacks and Discussion on their Case-Progressing Potential for Digital Forensics](https://arxiv.org/abs/1903.07703)
- 2019.03 [hexacorn] [PE Compilation Timestamps vs. forensics](http://www.hexacorn.com/blog/2019/03/11/pe-compilation-timestamps-vs-forensics/)
- 2019.03 [0x00sec] [A forensics repo?](https://0x00sec.org/t/a-forensics-repo/12157/)
- 2019.03 [crowdstrike] [AutoMacTC: Automating Mac Forensic Triage](https://www.crowdstrike.com/blog/automating-mac-forensic-triage/)
- 2019.03 [securityartwork] [Exchange forensics: The mysterious case of ghost mail (IV)](https://www.securityartwork.es/2019/03/06/exchange-forensics-the-mysterious-case-of-ghost-mail-iv/)
- 2019.03 [arxiv] [[1904.00734] Forensics Analysis of Xbox One Game Console](https://arxiv.org/abs/1904.00734)
- 2019.03 [ironcastle] [Special Webcast: SOF-ELK(R): A Free, Scalable Analysis Platform for Forensic, incident Response, and Security Operations – March 5, 2019 1:00pm US/Eastern](https://www.ironcastle.net/special-webcast-sof-elkr-a-free-scalable-analysis-platform-for-forensic-incident-response-and-security-operations-march-5-2019-100pm-us-eastern/)
- 2019.03 [securityartwork] [Exchange forensics: The mysterious case of ghost mail (III)](https://www.securityartwork.es/2019/03/05/exchange-forensics-the-mysterious-case-of-ghost-mail-iii/)
- 2019.03 [freebuf] [你可能没见过的流量取证](https://www.freebuf.com/articles/network/196374.html)
- 2019.03 [securityartwork] [Exchange forensics: The mysterious case of ghost mail (II)](https://www.securityartwork.es/2019/03/04/exchange-forensics-the-mysterious-case-of-ghost-mail-ii/)
- 2019.03 [HackerSploit] [Imago Forensics - Image Forensics Tutorial](https://www.youtube.com/watch?v=HIyObPWM6BM)
- 2019.02 [freebuf] [对恶意树莓派设备的取证分析](https://www.freebuf.com/articles/terminal/196085.html)
- 2019.02 [] [An Introduction to Exploratory Data Analysis with Network Forensics](https://401trg.com/introduction-to-exploratory-data-analysis/)
- 2019.02 [htbridge] [How to Use an Audit Log to Practice WordPress Forensics](https://www.htbridge.com/blog/benefits-activity-logs-wordpress-site.html)
- 2019.02 [htbridge] [How to Use an Audit Log to Practice WordPress Forensics](https://www.immuniweb.com/blog/benefits-activity-logs-wordpress-site.html)
- 2019.02 [arxiv] [[1903.03061] DIALOG: A framework for modeling, analysis and reuse of digital forensic knowledge](https://arxiv.org/abs/1903.03061)
- 2019.02 [arxiv] [[1903.01396] A complete formalized knowledge representation model for advanced digital forensics timeline analysis](https://arxiv.org/abs/1903.01396)
- 2019.02 [bhconsulting] [AWS Cloud: Proactive Security and Forensic Readiness – part 5](http://bhconsulting.ie/aws-incident-response/)
- 2019.02 [infosecinstitute] [Popular Computer Forensics Top 21 Tools [Updated for 2019]](https://resources.infosecinstitute.com/computer-forensics-tools/)
- 2019.02 [cybrary] [The Cost to Learn Computer Forensics](https://www.cybrary.it/2019/02/cost-learn-computer-forensics/)
- 2019.02 [cybrary] [“Ok Google. What is Forensic Analysis?”](https://www.cybrary.it/2019/02/ok-google-forensic-analysis/)
- 2019.02 [360] [从PowerShell内存中提取取证脚本内容](https://www.anquanke.com/post/id/170497/)
- 2019.02 [eforensicsmag] [How EnCase Software has Been Used Major Crime Cases (Plus how to use EnCase Forensic Imager Yourself) | By Brent Whitfield](https://eforensicsmag.com/how-encase-software-has-been-used-major-crime-cases-plus-how-to-use-encase-forensic-imager-yourself-by-brent-whitfield/)
- 2019.01 [4hou] [Linux内存取证：解析用户空间进程堆（下）](http://www.4hou.com/technology/15981.html)
- 2019.01 [4hou] [Linux内存取证：解析用户空间进程堆（中）](http://www.4hou.com/technology/15946.html)
- 2019.01 [cybrary] [Computer Forensics Jobs: How to get a job, and what you should know](https://www.cybrary.it/2019/01/computer-forensics-jobs-get-job/)
- 2019.01 [4hou] [Linux内存取证：解析用户空间进程堆（上）](http://www.4hou.com/technology/15826.html)
- 2019.01 [cybrary] [Computer Forensics Jobs: Is it really that difficult to enter the field?](https://www.cybrary.it/2019/01/computer-forensics-jobs-really-difficult-enter-field/)
- 2019.01 [checkpoint] [Check Point Forensic Files: GandCrab Returns with Friends (Trojans) | Check Point Software Blog](https://blog.checkpoint.com/2019/01/18/check-point-forensic-files-gandcrab-returns-with-friends-trojans/)
- 2019.01 [comae] [Leveraging Microsoft Graph API for memory forensics](https://medium.com/p/7ab7f9ea4d06)
- 2019.01 [cybrary] [Computer Forensics Jobs: Are there jobs available?](https://www.cybrary.it/2019/01/computer-forensics-jobs-jobs-available/)
- 2019.01 [leeholmes] [Extracting Forensic Script Content from PowerShell Process Dumps](https://www.leeholmes.com/blog/2019/01/17/extracting-forensic-script-content-from-powershell-process-dumps/)
- 2019.01 [freebuf] [iOS取证技巧：在无损的情况下完整导出SQLite数据库](https://www.freebuf.com/news/193684.html)
- 2019.01 [freebuf] [TorPCAP：Tor网络取证分析技术](https://www.freebuf.com/news/193660.html)
- 2019.01 [360] [Windows 注册表取证分析](https://www.anquanke.com/post/id/169435/)
- 2019.01 [freebuf] [Android取证：使用ADB和DD对文件系统做镜像](https://www.freebuf.com/articles/terminal/193354.html)
- 2019.01 [sans] [Go Big with Bootcamp for Advanced Memory Forensics and Threat Detection](https://digital-forensics.sans.org/blog/2019/01/09/go-big-with-bootcamp-for-advanced-memory-forensics-and-threat-detection)
- 2019.01 [fireeye] [Digging Up the Past: Windows Registry Forensics Revisited](https://www.fireeye.com/blog/threat-research/2019/01/digging-up-the-past-windows-registry-forensics-revisited.html)
- 2019.01 [sans] [SANS FOR585 Q&A: Smartphone Forensics - Questions answered](https://digital-forensics.sans.org/blog/2019/01/07/sans-for585-qa-smartphone-forensics-questions-answered)
- 2019.01 [redcanary] [Our Automation Solution, Exec, Now Features Forensics, Human Approvals, and More](https://www.redcanary.com/blog/introducing-forensics-human-approvals-more-for-exec/)
- 2019.01 [4hou] [CTF取证方法总结](http://www.4hou.com/web/15206.html)
- 2018.12 [hitbsecconf] [#HITB2018DXB: Offensive Memory Forensics - Hugo Teso](https://www.youtube.com/watch?v=P-OpyGJcMHE)
- 2018.12 [4hou] [Check Point取证报告：SandBlast客户端能够监测到无文件GandCrab](http://www.4hou.com/typ/15295.html)
- 2018.12 [4hou] [Apple FSEvents相关的取证问题总结](http://www.4hou.com/web/15205.html)
- 2018.12 [checkpoint] [Check Point Forensic Files: Fileless GandCrab As Seen by SandBlast Agent | Check Point Software Blog](https://blog.checkpoint.com/2018/12/17/fileless-gandcrab-sandblast-agent-malware-behavioral-guard/)
- 2018.12 [0x00sec] [Anti-forensic and File-less Malware](https://0x00sec.org/t/anti-forensic-and-file-less-malware/10008/)
- 2018.12 [sans] [The new version of SOF-ELK is here. Download, turn on, and get going on forensics analysis.](https://digital-forensics.sans.org/blog/2018/12/04/the-new-version-of-sof-elk-is-here-download-turn-on-and-get-going-on-forensics-analysis)
- 2018.12 [eforensicsmag] [(Not Quite) Snapchat Forensics | By Gary Hunter](https://eforensicsmag.com/not-quite-snapchat-forensics-by-gary-hunter/)
- 2018.12 [andreafortuna] [Android Forensics: imaging android filesystem using ADB and DD](https://www.andreafortuna.org/dfir/android-forensics-imaging-android-file-system-using-adb-and-dd/)
- 2018.12 [CodeColorist] [iOS forensics trick: pull databases w/o full backup](https://medium.com/p/c79fa32e5c14)
- 2018.11 [DEFCONConference] [DEF CON 26 DATA DUPLICATION VILLAGE -  Lior Kolnik  - The Memory Remains Cold Drive Memory Forensics](https://www.youtube.com/watch?v=sI6D_CrMr-Q)
- 2018.11 [volatility] [Malware and Memory Forensics Training in 2019!](https://volatility-labs.blogspot.com/2018/11/malware-and-memory-forensics-training.html)
- 2018.11 [eforensicsmag] [LOGICUBE INTRODUCES EDUCATIONAL VIDEO SERIES FOR IT’S NEXT-GENERATION FORENSIC IMAGER, FALCON-NEO | from Logicube](https://eforensicsmag.com/logicube-introduces-educational-video-series-for-its-next-generation-forensic-imager-falcon-neo-from-logicube/)
- 2018.11 [mac4n6] [Do it Live! Dynamic iOS Forensic Testing](https://www.mac4n6.com/blog/2018/11/25/do-it-live-dynamic-ios-forensic-testing)
- 2018.11 [arxiv] [[1811.09239] Digital Forensics for IoT and WSNs](https://arxiv.org/abs/1811.09239)
- 2018.11 [n0where] [Extract Digital Evidences From Images: Imago-Forensics](https://n0where.net/extract-digital-evidences-from-images-imago-forensics)
- 2018.11 [andreafortuna] [AutoTimeliner: automatically extract forensic timeline from memory dumps](https://www.andreafortuna.org/dfir/autotimeliner-automatically-extract-forensic-timeline-from-memory-dumps/)
- 2018.11 [freebuf] [PcapXray：一款功能强大的带有GUI的网络取证工具](https://www.freebuf.com/sectool/188508.html)
- 2018.11 [WildWestHackinFest] [Six Sick Systems, One Hour: Investigate with Host Forensics](https://www.youtube.com/watch?v=dq-hSl-uVbw)
- 2018.11 [arxiv] [[1811.01629] On the Transferability of Adversarial Examples Against CNN-Based Image Forensics](https://arxiv.org/abs/1811.01629)
- 2018.11 [DEFCONConference] [DEF CON 26 VOTING VILLAGE - Carsten Schurmann - A Comprehensive Forensic Analysis of WINVote Voting](https://www.youtube.com/watch?v=CXYCtSwkWf8)
- 2018.11 [arxiv] [[1811.00701] Towards the Development of Realistic Botnet Dataset in the Internet of Things for Network Forensic Analytics: Bot-IoT Dataset](https://arxiv.org/abs/1811.00701)
- 2018.10 [hackers] [Network Forensics: Wireshark Basics, Part 2](https://www.hackers-arise.com/single-post/2018/10/31/Network-Forensics-Wireshark-Basics-Part-2)
- 2018.10 [aliyun] [picoCTF2018 Writeup之Forensics篇](https://xz.aliyun.com/t/3098)
- 2018.10 [aliyun] [取证分析之发现Windows恶意程序执行痕迹](https://xz.aliyun.com/t/3067)
- 2018.10 [mac4n6] [Video Now Available - #DFIRFIT or BUST: A Forensic Exploration of iOS Health Data](https://www.mac4n6.com/blog/2018/10/28/video-now-available-dfirfit-or-bust-a-forensic-exploration-of-ios-health-data)
- 2018.10 [insanitybit] [Grapl: A Graph Platform for Detection, Forensics, and Incident Response](http://insanitybit.github.io/2018/10/20/grapl-a-graph-platform-for-detection-forensics-and-incident-response)
- 2018.10 [krypt3ia] [Ryan S. Lin: Cyber Stalking, VPN’s and Digital Forensics](https://krypt3ia.wordpress.com/2018/10/13/ryan-s-lin-cyber-stalking-vpns-and-digital-forensics/)
- 2018.10 [pediy] [[原创]取证分析之逆向服务器提权开启3389远程连接工具](https://bbs.pediy.com/thread-247239.htm)
- 2018.10 [malwarenailed] [Live forensic collection and triage using CyLR, CDQR and Skadi](http://malwarenailed.blogspot.com/2018/10/live-forensic-collection-and-triage.html)
- 2018.10 [insinuator] [Incident Analysis and Digital Forensics Summit 2018, 14th of November of 2018](https://insinuator.net/2018/10/incident-analysis-and-digital-forensics-summit-2018-14th-of-november-of-2018/)
- 2018.10 [SSTecTutorials] [USB Forensics - Find History of Connected USB | Data Stolen By USB?](https://www.youtube.com/watch?v=eO_3kSZgRzg)
- 2018.10 [elearnsecurity] [Top 5 Skills for a Career in Digital Forensics](https://blog.elearnsecurity.com/top-5-skills-for-a-career-in-digital-forensics.html)
- 2018.10 [eforensicsmag] [Threat Intelligence: Taking a Fresh Look at Digital Forensics Backlogs | By Jonathan Zhang](https://eforensicsmag.com/threat-intelligence-taking-a-fresh-look-at-digital-forensics-backlogs-by-jonathan-zhang/)
- 2018.10 [welivesecurity] [How to find forensic computer tools for each incident](https://www.welivesecurity.com/2018/10/03/it-forensic-tools-find-right-one/)
- 2018.10 [elcomsoft] [iOS Forensics Training in Vienna: 17-19 Oct 2018](https://blog.elcomsoft.com/2018/10/ios-forensics-training-in-vienna-17-19-oct-2018/)
- 2018.10 [andreafortuna] [Accessing Volume Shadow Copies within a forensic image](https://www.andreafortuna.org/dfir/accessing-volume-shadow-copies-within-a-forensic-image/)
- 2018.09 [hackers] [Network Forensics, Part 2: Detecting and Analyzing a SCADA DoS Attack](https://www.hackers-arise.com/single-post/2018/09/27/Network-Forensics-Part-2-Detecting-and-Analyzing-a-SCADA-DoS-Attack)
- 2018.09 [hackers] [Network Forensics, Wireshark Basics, Part 1](https://www.hackers-arise.com/single-post/2018/09/24/Network-Forensics-Wireshark-Basics-Part-1)
- 2018.09 [4hou] [如何对苹果设备进行云取证](http://www.4hou.com/technology/13592.html)
- 2018.09 [4hou] [是迫于压力还是心甘情愿？年底之前，苹果将完成和执法机构的取证工作对接](http://www.4hou.com/info/news/13523.html)
- 2018.09 [eforensicsmag] [Ethics and Forensics- Time To Take A Hard Look | By Marisa Dery](https://eforensicsmag.com/ethics-and-forensics-time-to-take-a-hard-look-by-marisa-dery/)
- 2018.09 [elcomsoft] [Cloud Forensics: Why, What and How to Extract Evidence](https://blog.elcomsoft.com/2018/09/cloud-forensics-why-what-and-how-to-extract-evidence/)
- 2018.09 [arxiv] [[1809.00745] IoTDots: A Digital Forensics Framework for Smart Environments](https://arxiv.org/abs/1809.00745)
- 2018.09 [bhconsulting] [AWS Cloud: Proactive Security and Forensic Readiness – part 4](http://bhconsulting.ie/aws-detective-controls/)
- 2018.08 [freebuf] [Hindsight：Google ChromeChromium历史访问记录取证工具](http://www.freebuf.com/sectool/179734.html)
- 2018.08 [arxiv] [[1808.01196] Enabling Trust in Deep Learning Models: A Digital Forensics Case Study](https://arxiv.org/abs/1808.01196)
- 2018.08 [eforensicsmag] [Tracking Photo’s Geo-location with GPS EXIF DATA – Forensic Analysis | By Bala Ganesh](https://eforensicsmag.com/tracking-photos-geo-location-with-gps-exif-data-forensic-analysis-by-bala-ganesh/)
- 2018.07 [arxiv] [[1807.10436] Emerging from The Cloud: A Bibliometric Analysis of Cloud Forensics Studies](https://arxiv.org/abs/1807.10436)
- 2018.07 [arxiv] [[1807.10438] Internet of Things Security and Forensics: Challenges and Opportunities](https://arxiv.org/abs/1807.10438)
- 2018.07 [arxiv] [[1807.10445] Greening Cloud-Enabled Big Data Storage Forensics: Syncany as a Case Study](https://arxiv.org/abs/1807.10445)
- 2018.07 [arxiv] [[1807.10359] B-CoC: A Blockchain-based Chain of Custody for Evidences Management in Digital Forensics](https://arxiv.org/abs/1807.10359)
- 2018.07 [arxiv] [[1807.10218] CloudMe Forensics: A Case of Big-Data Investigation](https://arxiv.org/abs/1807.10218)
- 2018.07 [arxiv] [[1807.10214] Cloud Storage Forensic: hubiC as a Case-Study](https://arxiv.org/abs/1807.10214)
- 2018.07 [pentesttoolz] [Hindsight – Internet History Forensics For Google Chrome/Chromium](https://pentesttoolz.com/2018/07/23/hindsight-internet-history-forensics-for-google-chrome-chromium/)
- 2018.07 [arxiv] [[1807.08264] Digital forensic investigation of two-way radio communication equipment and services](https://arxiv.org/abs/1807.08264)
- 2018.07 [] [Forensics Quickie: Identifying an Unknown GUID with Shellbags Explorer, Detailing Shell Item Extension Block 0xbeef0026, & Creative Cloud GUID Behavior](https://www.4n6k.com/2018/07/forensics-quickie-detailing-shell-item-guid-behavior-creative-cloud.html)
- 2018.07 [fireeye] [Leveraging Intelligence with FireEye Network Forensics](https://www.fireeye.com/blog/products-and-services/2018/07/leveraging-intelligence-with-fireeye-network-forensics.html)
- 2018.07 [NetflixTechBlog] [Netflix SIRT releases Diffy: A Differencing Engine for Digital Forensics in the Cloud](https://medium.com/p/37b71abd2698)
- 2018.07 [Sebdraven] [APT Sidewinder: Tricks powershell, Anti Forensics and execution side loading](https://medium.com/p/5bc1a7e7c84c)
- 2018.07 [eforensicsmag] [Digital Forensics – Tracking & Target Locating .Jpegs via Metadata (Exif) | By Hector Barquero](https://eforensicsmag.com/digital-forensics-tracking-target-locating-jpegs-via-metadata-exif-by-hector-barquero/)
- 2018.07 [4hou] [攻击者从台湾科技公司窃取证书用于Plead恶意软件活动](http://www.4hou.com/web/12550.html)
- 2018.07 [eforensicsmag] [Network Forensics Village | By Alexander Kot](https://eforensicsmag.com/network-forensics-village-by-alexander-kot/)
- 2018.07 [HACKADAY] [DataGram - Forensic Locksmithing](https://www.youtube.com/watch?v=h79mw8B1b8k)
- 2018.07 [pentesttoolz] [Guasap – WhatsApp Forensic Tool](https://pentesttoolz.com/2018/07/05/guasap-whatsapp-forensic-tool/)
- 2018.07 [hackread] [Top 7 Most Popular and Best Cyber Forensics Tools](https://www.hackread.com/top-7-cyber-forensic-tools/)
- 2018.06 [SecPgh] [Tactical, Practical, Digital Forensics - John Grim](https://www.youtube.com/watch?v=TQsf-MM95q0)
- 2018.06 [freebuf] [记一次服务器被入侵的调查取证](http://www.freebuf.com/articles/rookie/175370.html)
- 2018.06 [360] [企业APT攻击取证（windows版本）](https://www.anquanke.com/post/id/149182/)
- 2018.06 [elcomsoft] [iOS Forensic Toolkit 4.0 with Physical Keychain Extraction](https://blog.elcomsoft.com/2018/06/ios-forensic-toolkit-4-0-with-physical-keychain-extraction/)
- 2018.06 [countuponsecurity] [Digital Forensics – PlugX and Artifacts left behind](https://countuponsecurity.com/2018/06/20/digital-forensics-plugx-and-artifacts-left-behind/)
- 2018.06 [pediy] [[翻译]WhatsApp取证：对加密数据库进行解密和在尚未被Root的Android设备上提取已删除的消息](https://bbs.pediy.com/thread-228608.htm)
- 2018.06 [X13Cubed] [RDP Event Log Forensics](https://www.youtube.com/watch?v=myzG11BP3Sk)
- 2018.06 [mac4n6] [Presentation - #DFIRFIT or BUST: A Forensic Exploration of iOS Health Data (SANS DFIR Summit)](https://www.mac4n6.com/blog/2018/6/15/presentation-dfirfit-or-bust-a-forensic-exploration-of-ios-health-data-sans-dfir-summit)
- 2018.06 [0x00sec] [Intro to Digital Forensics [Part 2 - Methodology and Process Models]](https://0x00sec.org/t/intro-to-digital-forensics-part-2-methodology-and-process-models/7122/)
- 2018.06 [SecurityFest] [Solomon Sonya - Advanced Memory Forensics NextGen Actionable Threat Intelligence - SecurityFest 2018](https://www.youtube.com/watch?v=id_T7Z3tvWA)
- 2018.06 [andreafortuna] [Dumpzilla: a forensic tool to extract information from browsers based on Firefox](https://www.andreafortuna.org/dfir/dumpzilla-a-forensic-tool-to-extract-information-from-browsers-based-on-firefox/)
- 2018.06 [andreafortuna] [Using MFT anomalies to spot suspicious files in forensic analysis](https://www.andreafortuna.org/dfir/using-mft-anomalies-to-spot-suspicious-files-in-forensic-analysis/)
- 2018.05 [aliyun] [【取证分析】CentOS_5.5_安装GCC编译LiME](https://xz.aliyun.com/t/2346)
- 2018.04 [freebuf] [内存取证：查找Metasploit的Meterpreter踪迹](http://www.freebuf.com/sectool/168218.html)
- 2018.04 [360] [如何通过内存取证技术追踪Metasploit Meterpreter](https://www.anquanke.com/post/id/104322/)
- 2018.03 [freebuf] [如何对已损坏的SQLite数据库取证分析？](http://www.freebuf.com/articles/database/164644.html)
- 2018.03 [hackers] [Digital Forensics, Part 10: Mobile  Forensics (Android)](https://www.hackers-arise.com/single-post/2018/03/25/Digital-Forensics-Part-10-Mobile-Forensics-Android)
- 2018.03 [4hou] [数字取证调查中如何获取网络连接的时间戳？](http://www.4hou.com/technology/10790.html)
- 2018.03 [hackers] [Digital Forensics, Part 5: Analyzing the Windows Registry for Evidence](https://www.hackers-arise.com/single-post/2016/10/21/Digital-Forensics-Part-5-Analyzing-the-Windows-Registry-for-Evidence)
- 2018.03 [360] [WhatsApp取证技术：如何在未Root的Android设备上解密数据库](https://www.anquanke.com/post/id/98382/)
- 2018.03 [sec] [网络犯罪调查与电子数据取证](https://www.sec-un.org/%e7%bd%91%e7%bb%9c%e7%8a%af%e7%bd%aa%e8%b0%83%e6%9f%a5%e4%b8%8e%e7%94%b5%e5%ad%90%e6%95%b0%e6%8d%ae%e5%8f%96%e8%af%81/)
- 2018.02 [hackers] [Network Forensics, Part 1](https://www.hackers-arise.com/single-post/2018/02/28/Network-Forensics-Part-1)
- 2018.02 [freebuf] [iPhone X未能幸免 | 以色列取证企业发现解锁任意iPhone设备的方法](http://www.freebuf.com/news/163634.html)
- 2018.02 [hackingarticles] [Digital Forensics Investigation through OS Forensics (Part 3)](http://www.hackingarticles.in/digital-forensics-investigation-os-forensics-part-3/)
- 2018.02 [hackingarticles] [Convert Virtual Machine to Raw Images for Forensics (Qemu-Img)](http://www.hackingarticles.in/convert-virtual-machine-raw-images-forensics-qemu-img/)
- 2018.01 [hackingarticles] [Digital Forensics Investigation through OS Forensics (Part 2)](http://www.hackingarticles.in/digital-forensics-investigation-os-forensics-part-2/)
- 2018.01 [hackingarticles] [Digital Forensics Investigation using OS Forensics (Part1)](http://www.hackingarticles.in/digital-forensics-investigation-using-os-forensics-part1/)
- 2018.01 [hackingarticles] [Forensic Imaging through Encase Imager](http://www.hackingarticles.in/forensic-imaging-encase/)
- 2018.01 [hackingarticles] [Forensic Investigation of Nmap Scan using Wireshark](http://www.hackingarticles.in/forensic-investigation-of-nmap-scan-using-wireshark/)
- 2018.01 [boredhackerblog] [Digital Forensics and Law](http://www.boredhackerblog.info/2018/01/digital-forensics-and-law.html)
- 2018.01 [hackingarticles] [Forensic Data Carving using Foremost](http://www.hackingarticles.in/forensic-data-carving-using-foremost/)
- 2018.01 [4hou] [云存储服务的数字取证（下）](http://www.4hou.com/technology/9808.html)
- 2018.01 [4hou] [云存储服务的数字取证（上）](http://www.4hou.com/data/9807.html)
- 2018.01 [hackingarticles] [Forensics Tools in Kali](http://www.hackingarticles.in/forensics-tools-kali/)
- 2018.01 [hackingarticles] [Network Packet Forensic using Wireshark](http://www.hackingarticles.in/network-packet-forensic-using-wireshark/)
- 2017.12 [cert] [GreHack 2017 – Write Up Forensic 400](https://www.cert-devoteam.fr/publications/en/grehack-2017-write-up-forensic-400/)
- 2017.11 [freebuf] [著名开源网络取证工具Xplico远程未授权RCE漏洞](http://www.freebuf.com/sectool/154523.html)
- 2017.10 [freebuf] [反取证技术：内核模式下的进程隐蔽](http://www.freebuf.com/articles/web/148515.html)
- 2017.10 [4hou] [内存取证分析的实战演练](http://www.4hou.com/technology/5860.html)
- 2017.10 [n0where] [Wireless Monitoring, Intrusion Detection & Forensics: Nzyme](https://n0where.net/wireless-monitoring-intrusion-detection-forensics-nzyme)
- 2017.09 [sans] [Forensic use of mount --bind](https://isc.sans.edu/forums/diary/Forensic+use+of+mount+bind/22854/)
- 2017.09 [360] [PCRT：一款自动化检测修复PNG损坏的取证工具](https://www.anquanke.com/post/id/86793/)
- 2017.09 [elcomsoft] [New Security Measures in iOS 11 and Their Forensic Implications](https://blog.elcomsoft.com/2017/09/new-security-measures-in-ios-11-and-their-forensic-implications/)
- 2017.08 [freebuf] [内存取证三项CTF赛题详解](http://www.freebuf.com/articles/rookie/145262.html)
- 2017.08 [aliyun] [威胁猎杀与主动取证](https://xz.aliyun.com/t/1057)
- 2017.08 [securelayer7] [Memory Forensics & Reverse Engineering : Thick Client Penetration Testing – Part 4](http://blog.securelayer7.net/static-analysismemory-forensics-reverse-engineering-thick-client-penetration-testing-part-4/)
- 2017.08 [freebuf] [详解Windows注册表分析取证](http://www.freebuf.com/articles/system/142417.html)
- 2017.08 [pediy] [[翻译]CTF取证类题目指南](https://bbs.pediy.com/thread-220021.htm)
- 2017.07 [aliyun] [[ISS 2017]电子数据取证 议题分享一：网络犯罪魔与道：过去、现在、未来](https://xz.aliyun.com/t/731)
- 2017.07 [aliyun] [[ISS 2017]电子数据取证 议题分享二：计算机取证，科学?](https://xz.aliyun.com/t/732)
- 2017.07 [4hou] [BlackHat2017热点之DefPloreX---大规模网络犯罪取证的机器学习工具](http://www.4hou.com/tools/6881.html)
- 2017.07 [trendmicro] [DefPloreX: A Machine-Learning Toolkit for Large-scale eCrime Forensics](https://blog.trendmicro.com/trendlabs-security-intelligence/defplorex-machine-learning-toolkit-large-scale-ecrime-forensics/)
- 2017.07 [securelist] [Bitscout – The Free Remote Digital Forensics Tool Builder](https://securelist.com/bitscout-the-free-remote-digital-forensics-tool-builder/78991/)
- 2017.06 [360] [数字取证技术——NTFS更改日志](https://www.anquanke.com/post/id/86265/)
- 2017.06 [secist] [22款受欢迎的计算机取证工具](http://www.secist.com/archives/3743.html)
- 2017.06 [freebuf] [22款受欢迎的计算机取证工具](http://www.freebuf.com/sectool/136921.html)
- 2017.06 [4hou] [工具推荐：22款最流行的计算机取证工具【2017年更新版】](http://www.4hou.com/tools/5331.html)
- 2017.06 [nicoleibrahim] [Apple FSEvents Forensics](http://nicoleibrahim.com/apple-fsevents-forensics/)
- 2017.06 [freebuf] [基于bro的计算机入侵取证实战分析](http://www.freebuf.com/articles/system/135843.html)
- 2017.06 [n0where] [Digital Forensics Platform: Autopsy](https://n0where.net/digital-forensics-platform-autopsy)
- 2017.05 [360] [Linux取证技术实践](https://www.anquanke.com/post/id/86177/)
- 2017.05 [countuponsecurity] [Digital Forensics – NTFS Change Journal](https://countuponsecurity.com/2017/05/25/digital-forensics-ntfs-change-journal/)
- 2017.05 [freebuf] [计算机取证在企业安全中的实际应用](http://www.freebuf.com/articles/others-articles/134283.html)
- 2017.04 [hackingarticles] [Mobile Forensics Investigation using Cellebrite UFED](http://www.hackingarticles.in/mobile-forensics-investigation-using-cellebrite-ufed/)
- 2017.04 [ionize] [BSides Canberra 2017 CTF Writeup – Forensics – Capture This Challenge](https://ionize.com.au/bsides-canberra-2017-ctf-writeup-forensics-capture-challenge/)
- 2017.03 [4hou] [反取证、密码学、逆向工程软件…… 10大最好的网络安全Reddit都在这儿](http://www.4hou.com/info/news/3959.html)
- 2017.03 [freebuf] [数字取证技术 ：Windows内存信息提取](http://www.freebuf.com/articles/system/129463.html)
- 2017.03 [csyssec] [名人课堂-高级数字取证与数据逆向工程](http://www.csyssec.org/20170306/course-zhiqianglin1/)
- 2017.01 [n0where] [Open Source File System Digital Forensics: The Sleuth Kit](https://n0where.net/open-source-file-system-digital-forensics-the-sleuth-kit)
- 2017.01 [securestate] [CTF Example – Forensics](https://warroom.securestate.com/forensic-files-a-ctf-beginners-guide/)
- 2017.01 [welivesecurity] [Forensic analysis techniques for digital imaging](https://www.welivesecurity.com/2017/01/13/forensic-analysis-techniques-digital-imaging/)
- 2017.01 [freebuf] [为保护隐私而生，反取证操作系统：kodachi](http://www.freebuf.com/sectool/124486.html)
- 2017.01 [n0where] [Secure Anti Forensic Anonymous Operating System: kodachi](https://n0where.net/secure-anti-forensic-anonymous-operating-system-kodachi)
- 2016.12 [lightless] [SECCON2016取证题WriteUP](https://lightless.me/archives/SECCON-2016-Forensics-WP.html)
- 2016.11 [hackers] [Digital Forensics, Part 8: Live Analysis with sysinternals](https://www.hackers-arise.com/single-post/2016/11/29/Digital-Forensics-Part-7-Live-Analysis-with-sysinternals)
- 2016.11 [hackers] [Digital Forensics, Part 7: Browser Forensics](https://www.hackers-arise.com/single-post/2016/11/17/Digital-Forensics-Part-7-Browser-Forensics)
- 2016.11 [n0where] [PowerShell Digital Forensics: PowerForensics](https://n0where.net/powershell-digital-forensics-powerforensics)
- 2016.11 [hackers] [Digital Forensics, Part 6: Analyzing Windows Pre-fetch Files for Evidence](https://www.hackers-arise.com/single-post/2016/11/02/Digital-Forensics-Part-6-Analyzing-Windows-Pre-fetch-Files-for-Evidence)
- 2016.10 [hackers] [Digital Forensics, Part 4: Finding Key Evidence in the Forensic Image](https://www.hackers-arise.com/single-post/2016/10/14/Digital-Forensics-Part-4-Finding-Key-Evidence-in-the-Forensic-Image)
- 2016.10 [hackers] [Digital Forensics, Part 3: Recovering Deleted Files](https://www.hackers-arise.com/single-post/2016/10/10/Digital-Forensics-Part-3-Recovering-Deleted-Files)
- 2016.10 [hackers] [Anti-Forensics: How to Clear Evidence Like Hillary Clinton](https://www.hackers-arise.com/single-post/2016/09/06/Anti-Forensics-How-to-Clean-Evidence-Like-Hillary-Clinton)
- 2016.09 [hackers] [Digital Forensics, Part 2:  Live Memory Acquisition and Analysis](https://www.hackers-arise.com/single-post/2016/09/27/Digital-Forensics-Part-2-Live-Memory-Acquisition-and-Analysis)
- 2016.09 [sans] [Back in Time Memory Forensics](https://isc.sans.edu/forums/diary/Back+in+Time+Memory+Forensics/21527/)
- 2016.09 [hackers] [Digital Forensics, Part 1: Capturing a Forensically Sound Image](https://www.hackers-arise.com/single-post/2016/09/19/Digital-Forensics-Part-1-Capturing-a-Forensically-Sound-Image)
- 2016.09 [sans] [Windows Events log for IR/Forensics ,Part 2](https://isc.sans.edu/forums/diary/Windows+Events+log+for+IRForensics+Part+2/21501/)
- 2016.09 [n0where] [Windows Forensic Data Collection: IR-rescue](https://n0where.net/windows-forensic-data-collection-ir-rescue)
- 2016.09 [sans] [Windows Events log for IR/Forensics ,Part 1](https://isc.sans.edu/forums/diary/Windows+Events+log+for+IRForensics+Part+1/21493/)
- 2016.09 [n0where] [Forensic File System Reconstruction: RecuperaBit](https://n0where.net/forensic-file-system-reconstruction-recuperabit)
- 2016.08 [n0where] [USB Anti Forensic Tool: usbdeath](https://n0where.net/usb-anti-forensic-tool-usbdeath)
- 2016.08 [rapid7] [Using Log Data as Forensic Evidence](https://blog.rapid7.com/2016/08/12/using-log-data-as-forensic-evidence/)
- 2016.08 [sans] [Looking for the insider: Forensic Artifacts on iOS Messaging App](https://isc.sans.edu/forums/diary/Looking+for+the+insider+Forensic+Artifacts+on+iOS+Messaging+App/21363/)
- 2016.08 [n0where] [OS X Forensic Evidence Collection: OSXCollector](https://n0where.net/os-x-forensic-evidence-collection-osxcollector)
- 2016.07 [n0where] [Incident Response Forensic Framework: nightHawk Response](https://n0where.net/incident-response-forensic-framework-nighthawk-response)
- 2016.07 [n0where] [Offline Digital Forensics Tool for Binary Files: ByteForce](https://n0where.net/offline-digital-forensics-tool-byteforce)
- 2016.06 [hackers] [Covering your BASH Shell Tracks- Anti-Forensics](https://www.hackers-arise.com/single-post/2016/06/20/Covering-your-BASH-Shell-Tracks-AntiForensics)
- 2016.06 [rapid7] [Trip Report: Techno Security & Forensics Investigations Conference](https://blog.rapid7.com/2016/06/09/trip-report-techno-security-forensics-investigations-conference/)
- 2016.06 [sans] [Performing network forensics with Dshell. Part 2: Decoder development process](https://isc.sans.edu/forums/diary/Performing+network+forensics+with+Dshell+Part+2+Decoder+development+process/21123/)
- 2016.05 [sans] [Performing network forensics with Dshell. Part 1: Basic usage](https://isc.sans.edu/forums/diary/Performing+network+forensics+with+Dshell+Part+1+Basic+usage/21035/)
- 2016.05 [n0where] [Open Source Intelligence and Forensics : Maltego](https://n0where.net/open-source-intelligence-and-forensics-maltego)
- 2016.04 [sans] [An Introduction to Mac memory forensics](https://isc.sans.edu/forums/diary/An+Introduction+to+Mac+memory+forensics/20989/)
- 2016.04 [n0where] [Advanced Forensics File Format: AFF4](https://n0where.net/advanced-forensics-file-format-aff4)
- 2016.03 [sans] [Improving Bash Forensics Capabilities](https://isc.sans.edu/forums/diary/Improving+Bash+Forensics+Capabilities/20887/)
- 2016.03 [sans] [Forensicating Docker, Part 1](https://isc.sans.edu/forums/diary/Forensicating+Docker+Part+1/20835/)
- 2016.03 [hackingarticles] [Wifi Forensic Investigation using Wifihistoryview](http://www.hackingarticles.in/wifi-forensic-investigation-using-wifihistoryview/)
- 2016.02 [freebuf] [针对爱尔兰DDoS攻击的取证分析](http://www.freebuf.com/articles/network/96179.html)
- 2016.02 [nsfocus] [加强调查取证，夯实威胁情报基础](http://blog.nsfocus.net/security-incident-investigation-to-threat-intelligence/)
- 2016.02 [360] [新型DDOS攻击分析取证](https://www.anquanke.com/post/id/83443/)
- 2016.01 [freebuf] [Joy：捕获数据包、分析网络流量数据、网络取证及安全监控工具](http://www.freebuf.com/sectool/93017.html)
- 2016.01 [freebuf] [分析取证指南：取证工具推荐](http://www.freebuf.com/sectool/92946.html)
- 2016.01 [sans] [toolsmith #112: Red vs Blue - PowerSploit vs PowerForensics](https://isc.sans.edu/forums/diary/toolsmith+112+Red+vs+Blue+PowerSploit+vs+PowerForensics/20579/)
- 2015.12 [freebuf] [针对国外一款超火约会软件Tinder的取证分析](http://www.freebuf.com/articles/terminal/91546.html)
- 2015.12 [freebuf] [开源网络取证工具Xplico](http://www.freebuf.com/sectool/88496.html)
- 2015.11 [secist] [调查取证之图像还原](http://www.secist.com/archives/2131.html)
- 2015.11 [secist] [调查取证之文字还原](http://www.secist.com/archives/2110.html)
- 2015.11 [n0where] [Network Forensic Analysis Tool: Xplico](https://n0where.net/network-forensic-analysis-tool-xplico)
- 2015.11 [n0where] [Digital Forensics Distro: CAINE](https://n0where.net/digital-forensics-distro-caine)
- 2015.11 [hackingarticles] [Forensic Investigation of Any Mobile Phone with MOBILedit Forensic](http://www.hackingarticles.in/forensic-investigation-of-any-mobile-phone-with-mobiledit-forensic/)
- 2015.10 [hackingarticles] [Android Mobile Device Forensics with Mobile Phone Examiner Plus](http://www.hackingarticles.in/android-mobile-device-forensics-with-mobile-phone-examiner-plus/)
- 2015.10 [360] [WMI 的攻击，防御与取证分析技术之攻击篇](https://www.anquanke.com/post/id/82798/)
- 2015.10 [hackingarticles] [How to Create a Forensic Image of Android Phone using Magnet Acquire](http://www.hackingarticles.in/how-to-create-a-forensic-image-of-andorid-phone-using-magnet-acquire/)
- 2015.10 [hackingarticles] [Forensics Investigation of Android Phone using Andriller](http://www.hackingarticles.in/forensics-investigation-of-android-phone-using-andriller/)
- 2015.10 [hackingarticles] [Logical Forensics of an Android Device using AFLogical](http://www.hackingarticles.in/logical-forensics-of-an-android-device-using-aflogical/)
- 2015.10 [hackingarticles] [SANTOKU Linux- Overview of Mobile Forensics Operating System](http://www.hackingarticles.in/santoku-linux-overview-of-mobile-forensics-operating-system/)
- 2015.10 [hackingarticles] [Forensics Analysis of Pagefile and hibersys File in Physical Memory](http://www.hackingarticles.in/forensics-analysis-of-pagefile-and-hibersys-file-in-physical-memory/)
- 2015.09 [hackingarticles] [4 ways Capture Memory for Analysis (Memory Forensics)](http://www.hackingarticles.in/4-ways-capture-memory-for-analysis-memory-forensics/)
- 2015.09 [hackingarticles] [Forensic Investigation of RAW Image using Forensics Explorer (Part 1)](http://www.hackingarticles.in/forensic-investigation-of-raw-image-using-forensics-explorer-part-1/)
- 2015.09 [hackingarticles] [Forensic   Investigation Tutorial Using DEFT](http://www.hackingarticles.in/forensic-investigation-tutorial-using-deft/)
- 2015.09 [freebuf] [“短信拦截马”黑色产业链与溯源取证研究](http://www.freebuf.com/articles/terminal/77331.html)
- 2015.07 [hackingarticles] [Forensics Investigon of RAW Images using Belkasoft Evidence Center](http://www.hackingarticles.in/forensics-investigon-of-raw-images-using-belkasoft-evidence-center/)
- 2015.07 [hackingarticles] [How to Clone Drive for Forensics Purpose](http://www.hackingarticles.in/how-to-clone-drive-for-forensics-purpose/)
- 2015.06 [hackingarticles] [Best of Computer Forensics Tutorials](http://www.hackingarticles.in/best-of-computer-forensics-tutorials/)
- 2015.06 [hackingarticles] [Forensics Investigation of Deleted Files in a Drive](http://www.hackingarticles.in/forensics-investigation-of-deleted-files-in-a-drive/)
- 2015.06 [hackingarticles] [Comparison of two Files for forensics investigation by Compare IT](http://www.hackingarticles.in/comparison-of-two-files-for-forensics-investigation-by-compare-it/)
- 2015.06 [hackingarticles] [Live Forensics Case Investigation using Autopsy](http://www.hackingarticles.in/live-forensics-case-investigation-using-autopsy/)
- 2015.06 [hackingarticles] [How to Install Digital Forensics Framework in System](http://www.hackingarticles.in/how-to-install-digital-forensics-framework-in-system/)
- 2015.06 [hackingarticles] [Forensics Investigation of Facebook, Skype, and Browsers in RAW Image using IEF (Internet Evidence Finder)](http://www.hackingarticles.in/forensics-investigation-of-facebook-skype-and-browsers-in-raw-image-using-ief-internet-evidence-finder/)
- 2015.06 [hackingarticles] [How to Create Drive Image for Forensic Purpose using Forensic Replicator](http://www.hackingarticles.in/how-to-create-drive-image-for-forensic-purpose-using-forensic-replicator/)
- 2015.06 [hackingarticles] [Outlook Forensics Investigation using E-Mail Examiner](http://www.hackingarticles.in/outlook-forensics-investigation-using-e-mail-examiner/)
- 2015.06 [hackingarticles] [How to Preserve Forensics Image file Timestamp](http://www.hackingarticles.in/how-to-preserve-forensics-image-file-timestamp/)
- 2015.05 [hackingarticles] [Forensics Investigation of Evidence RAW Image using OS Forensics Tool](http://www.hackingarticles.in/forensics-investigation-of-evidence-raw-image-using-os-forensics-tool/)
- 2015.05 [hackingarticles] [How to Create and Convert RAW Image in Encase and AFF Format using Forensics Imager](http://www.hackingarticles.in/how-to-create-and-convert-raw-image-in-encase-and-aff-format-using-forensics-imager/)
- 2015.05 [hackingarticles] [How to Mount Forensics image as a Drive using P2 eXplorer Pro](http://www.hackingarticles.in/how-to-mount-forensics-image-as-a-drive-using-p2-explorer-pro/)
- 2015.05 [hackingarticles] [How to gather Forensics Investigation Evidence using ProDiscover Basic](http://www.hackingarticles.in/how-to-gather-forensics-investigation-evidence-using-prodiscover-basic/)
- 2015.05 [hackingarticles] [How to study Forensics Evidence of PC using P2 Commander (Part 2)](http://www.hackingarticles.in/how-to-study-forensics-evidence-of-pc-using-p2-commander-part-2/)
- 2015.05 [hackingarticles] [How to Collect Forensics Evidence of PC using P2 Commander (Part 1)](http://www.hackingarticles.in/how-to-collect-forensics-evidence-of-pc-using-p2-commander-part-1/)
- 2015.05 [hackingarticles] [How to Create Forensics Image of PC using R-Drive Image](http://www.hackingarticles.in/how-to-create-forensics-image-of-pc-using-r-drive-image/)
- 2015.04 [hackingarticles] [Forensic Investigation of victim pc using Autopsy](http://www.hackingarticles.in/forensic-investigation-of-victim-pc-using-autopsy/)
- 2015.04 [hackingarticles] [Forensic Investigation of any Twitter account](http://www.hackingarticles.in/forensic-investigation-of-any-twitter-account/)
- 2015.04 [hackingarticles] [How to perform Forensic Investigation on user Linkedin Account](http://www.hackingarticles.in/how-to-perform-forensic-investigation-on-user-linkedin-account/)
- 2015.04 [hackingarticles] [How to Perform Forensic Investigation on YouTube](http://www.hackingarticles.in/how-to-perform-forensic-investigation-on-youtube/)
- 2015.04 [hackingarticles] [Forensic Investigation of any FaceBook Profile](http://www.hackingarticles.in/forensic-investigation-of-any-facebook-profile/)
- 2015.04 [sans] [Memory Forensics Of Network Devices](https://isc.sans.edu/forums/diary/Memory+Forensics+Of+Network+Devices/19591/)
- 2015.03 [hackingarticles] [How to find the usage of files in Remote victim PC (Remote PC Forensics)](http://www.hackingarticles.in/how-to-find-the-usage-of-files-in-remote-victim-pc-remote-pc-forensics/)
- 2015.03 [] [Web日志取证分析工具](http://www.91ri.org/12592.html)
- 2015.02 [] [电子取证实例：基于磁盘的数据取证](http://www.91ri.org/12339.html)
- 2015.02 [n0where] [Forensic Data Extraction: Bulk Extractor](https://n0where.net/forensic-data-extraction-bulk-extractor)
- 2015.02 [] [从一次取证到反渗透](http://www.91ri.org/12308.html)
- 2015.02 [sans] [Another Network Forensic Tool for the Toolbox - Dshell](https://isc.sans.edu/forums/diary/Another+Network+Forensic+Tool+for+the+Toolbox+Dshell/19277/)
- 2015.02 [freebuf] [电子取证实例：基于文件系统的磁盘数据取证分析](http://www.freebuf.com/articles/system/57804.html)
- 2015.01 [n0where] [Dshell – Network Forensic Analysis Framework](https://n0where.net/dshell-network-forensic-analysis-framework)
- 2015.01 [hackingarticles] [How to Collect Email Evidence in Victim PC (Email Forensics)](http://www.hackingarticles.in/how-to-collect-email-evidence-in-victim-pc-email-forensics/)
- 2015.01 [hackingarticles] [Forensics Analysis of Social Media Sites like Facebook, Twitter, LinkedIn](http://www.hackingarticles.in/forensics-analysis-of-social-media-sites-like-facebook-twitter-linkedin/)
- 2014.11 [freebuf] [Linux入侵取证：从一次应急事件讲起](http://www.freebuf.com/articles/system/50728.html)
- 2014.10 [] [云端博弈——云安全入侵取证及思考](http://www.91ri.org/11170.html)
- 2014.10 [tencent] [云端博弈——云安全入侵取证及思考](https://security.tencent.com/index.php/blog/msg/72)
- 2014.10 [sec] [容易被忽略的Anti-APT产品-网络取证工具NFT](https://www.sec-un.org/overlooked-anti-apt-products-network-forensic-tools-nft/)
- 2014.08 [n0where] [Digital Forensics Toolkit: DEFT](https://n0where.net/digital-forensics-toolkit-deft)
- 2014.08 [freebuf] [FB公开课录像：隐蔽通信（FQ）和侦查取证那些事儿](http://www.freebuf.com/video/40500.html)
- 2014.07 [freebuf] [FreeBuf公开课（直播课程）：隐蔽通信（FQ）和侦查取证那些事儿](http://www.freebuf.com/fevents/39454.html)
- 2014.05 [freebuf] [电子取证之Linux PCI分析](http://www.freebuf.com/articles/system/35490.html)
- 2014.04 [hackingarticles] [Hack MOBILedit Forensic 6.9 Registration (Easy Way)](http://www.hackingarticles.in/hack-mobiledit-forensic-6-9-registration-easy-way/)
- 2014.03 [freebuf] [走进计算机取证分析的神秘世界](http://www.freebuf.com/articles/terminal/29653.html)
- 2014.02 [hackingarticles] [Forensics Investigation of Remote PC (Part 2)](http://www.hackingarticles.in/forensics-investigation-of-remote-pc-part-2/)
- 2014.02 [hackingarticles] [Forensics Investigation of Remote PC (Part 1)](http://www.hackingarticles.in/forensics-investigation-of-remote-pc-part-1/)
- 2014.01 [freebuf] [渗透测试中的冷却启动攻击和其他取证技术](http://www.freebuf.com/articles/system/23409.html)
- 2013.12 [pediy] [[原创]xls文件取证](https://bbs.pediy.com/thread-182739.htm)
- 2013.11 [n0where] [Network Takeover Forensic Analysis: FS-NyarL](https://n0where.net/network-takeover-forensic-analysis-fs-nyarl)
- 2013.05 [sans] [Call for Papers - 4th annual Forensics and Incident Response Summit EU](https://isc.sans.edu/forums/diary/Call+for+Papers+4th+annual+Forensics+and+Incident+Response+Summit+EU/15809/)
- 2013.05 [freebuf] [移动设备取证、恶意软件分析和安全测试套件—Santoku](http://www.freebuf.com/sectool/9280.html)
- 2013.05 [n0where] [Mobile Forensics: Santoku](https://n0where.net/mobile-forensics-santoku)
- 2013.04 [freebuf] [针对取证的GNU/Linux发行版: PALADIN](http://www.freebuf.com/sectool/8232.html)
- 2013.01 [pediy] [[推荐]Android取证和安全测试开放课程](https://bbs.pediy.com/thread-160891.htm)
- 2012.10 [welivesecurity] [PC Support Scams: a Forensic View](https://www.welivesecurity.com/2012/10/30/pc-support-scams-a-forensic-view/)
- 2012.10 [welivesecurity] [Defeating anti-forensics in contemporary complex threats](https://www.welivesecurity.com/2012/10/11/defeating-anti-forensics-in-contemporary-complex-threats/)
- 2012.09 [freebuf] [[更新]GUI界面文件信息取证分析工具-FileInfo V6.0](http://www.freebuf.com/sectool/5740.html)
- 2012.07 [freebuf] [渗透测试、电子取证系统 – Bugtraq-I](http://www.freebuf.com/sectool/5165.html)
- 2012.07 [freebuf] [Iphone取证(一)](http://www.freebuf.com/articles/wireless/5009.html)
- 2012.06 [freebuf] [开源数字调查/取证工具 – Sleuth Kit v4.0.0 Beta1](http://www.freebuf.com/sectool/3097.html)
- 2012.05 [freebuf] [数字取证工具包-SIFT](http://www.freebuf.com/sectool/1315.html)
- 2012.03 [hackingarticles] [Antivirus Forensics Tools](http://www.hackingarticles.in/antivirus-forensics-tools/)
- 2012.02 [hackingarticles] [BFT (Browser Forensic Tool )](http://www.hackingarticles.in/bft-browser-forensic-tool/)
- 2012.01 [rapid7] [Metasploit Updated: Forensics, SCADA, SSH Public Keys, and More](https://blog.rapid7.com/2012/01/19/metasploit-framework-updated/)
- 2012.01 [rapid7] [Adventures in the Windows NT Registry: A step into the world of Forensics and Information Gathering](https://blog.rapid7.com/2012/01/16/adventures-in-the-windows-nt-registry-a-step-into-the-world-of-forensics-and-ig/)
- 2011.11 [hackingarticles] [How to View Windows system reboot Date and Time (Windows Forensics)](http://www.hackingarticles.in/how-to-view-windows-system-reboot-date-and-time-windows-forensics/)
- 2011.09 [sans] [Analyzing Mobile Device Malware - Honeynet Forensic Challenge 9 and Some Tools](https://isc.sans.edu/forums/diary/Analyzing+Mobile+Device+Malware+Honeynet+Forensic+Challenge+9+and+Some+Tools/11521/)
- 2011.09 [hackingarticles] [Find Last Connected USB on your system (USB Forensics)](http://www.hackingarticles.in/find-last-connected-usb-on-your-system-usb-forensics/)
- 2011.09 [hackingarticles] [List of Computer Forensics Tools (Part 1)](http://www.hackingarticles.in/list-of-computer-forensics-tools/)
- 2010.11 [trendmicro] [STUXNET Scanner: A Forensic Tool](https://blog.trendmicro.com/trendlabs-security-intelligence/stuxnet-scanner-a-forensic-tool/)
- 2010.09 [sans] [Quick Forensic Challenge](https://isc.sans.edu/forums/diary/Quick+Forensic+Challenge/9598/)
- 2010.06 [sans] [New Honeynet Project Forensic Challenge](https://isc.sans.edu/forums/diary/New+Honeynet+Project+Forensic+Challenge/8905/)
- 2010.05 [sans] [SANS 2010 Digital Forensics Summit - APT Based Forensic Challenge](https://isc.sans.edu/forums/diary/SANS+2010+Digital+Forensics+Summit+APT+Based+Forensic+Challenge/8839/)
- 2010.05 [sans] [2010 Digital Forensics and Incident Response Summit](https://isc.sans.edu/forums/diary/2010+Digital+Forensics+and+Incident+Response+Summit/8830/)
- 2010.04 [sans] [Network and process forensics toolset](https://isc.sans.edu/forums/diary/Network+and+process+forensics+toolset/8611/)
- 2010.01 [sans] [Forensic challenges](https://isc.sans.edu/forums/diary/Forensic+challenges/8014/)
- 2009.12 [sans] [Anti-forensics, COFEE vs. DECAF](https://isc.sans.edu/forums/diary/Antiforensics+COFEE+vs+DECAF/7741/)
- 2009.08 [sans] [Network Forensics Puzzle Contest](https://isc.sans.edu/forums/diary/Network+Forensics+Puzzle+Contest/6997/)
- 2009.08 [sans] [Forensics: Mounting partitions from full-disk 'dd' images](https://isc.sans.edu/forums/diary/Forensics+Mounting+partitions+from+fulldisk+dd+images/6991/)
- 2009.07 [riusksk] [Windows平台下的监控取证技术](http://riusksk.me/2009/07/07/Windows平台下的监控取证技术/)
- 2009.07 [pediy] [[原创]Windows平台下的取证技术](https://bbs.pediy.com/thread-92786.htm)
- 2008.10 [sans] [Day 19 - Eradication:  Forensic Analysis Tools - What Happened?](https://isc.sans.edu/forums/diary/Day+19+Eradication+Forensic+Analysis+Tools+What+Happened/5200/)
- 2005.05 [sans] [Firefox 1.0.4; DNSSEC Tools; Phisher's benefit use Google link; Viewing Chat Logs; Web Browser Forensics; Gecko Based Browers HTTP Authentication Prompt Vulnerability](https://isc.sans.edu/forums/diary/Firefox+104+DNSSEC+Tools+Phishers+benefit+use+Google+link+Viewing+Chat+Logs+Web+Browser+Forensics+Gecko+Based+Browers+HTTP+Authentication+Prompt+Vulnerability/536/)


***


## <a id="bc6550163d1995f3ce6323404e2cec28"></a>Volatility


- 2019.11 [volatility] [Results from the 2019 Volatility Contests are in!](https://volatility-labs.blogspot.com/2019/11/results-from-2019-volatility-contests.html)
- 2019.10 [volatility] [Announcing the Volatility 3 Public Beta!](https://volatility-labs.blogspot.com/2019/10/announcing-volatility-3-public-beta.html)
- 2019.10 [countuponsecurity] [Notes on Linux Memory Analysis – LiME, Volatility and LKM’s](https://countuponsecurity.com/2019/10/14/notes-on-linux-memory-analysis-lime-volatility-and-lkms/)
- 2019.10 [doyler] [BofA Forensics and Volatility for the Win (DerbyCon 9)](https://www.doyler.net/security-not-included/bofa-forensics-derbycon-9-ctf)
- 2019.07 [cristivlad25] [Practical Pentesting - How to do Memory Forensics with Volatility - AttackDefense Labs](https://www.youtube.com/watch?v=epPEA6Cw3_Q)
- 2019.06 [infosecinstitute] [Ransomware analysis with Volatility](https://resources.infosecinstitute.com/ransomware-analysis-with-volatility/)
- 2019.04 [andreafortuna] [How to analyze a VMware memory image with Volatility](https://www.andreafortuna.org/2019/04/03/how-to-analyze-a-vmware-memory-image-with-volatility/)
- 2019.03 [4hou] [基础事件响应中的Volatility工作流程](https://www.4hou.com/web/16598.html)
- 2019.01 [sans] [Mac Memory Analysis with Volatility](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1493741844.pdf)
- 2019.01 [sans] [Android Mind Reading - Memory Acquisition and Analysis with LiME and Volatility](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1493741700.pdf)
- 2019.01 [sans] [Volatility Bot](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1492186622.pdf)
- 2018.11 [volatility] [Results from the 2018 Volatility Contests are in!](https://volatility-labs.blogspot.com/2018/11/results-from-annual-2018-volatility-contests.html)
- 2018.08 [jpcert] [Volatility Plugin for Detecting Cobalt Strike Beacon](https://blog.jpcert.or.jp/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html)
- 2018.07 [aliyun] [利用Volatility进行入侵痕迹分析](https://xz.aliyun.com/t/2497)
- 2018.07 [andreafortuna] [Digital forensics chronicles: image identification issues on large memory dump with Volatility](https://www.andreafortuna.org/dfir/digital-forensics-chronicles-image-identification-issues-on-large-memory-dump-with-volatility/)
- 2018.07 [andreafortuna] [Finding malware on memory dumps using Volatility and Yara rules](https://www.andreafortuna.org/dfir/finding-malware-on-memory-dumps-using-volatility-and-yara-rules/)
- 2018.05 [pentesttoolz] [Linux Screenshot XWindows – Volatility Plugin To Extract X Screenshots From A Memory Dump](https://pentesttoolz.com/2018/05/22/linux-screenshot-xwindows-volatility-plugin-to-extract-x-screenshots-from-a-memory-dump/)
- 2018.05 [volatility] [The 6th Annual Volatility Plugin Contest and the Inaugural Volatility Analysis Contest!](https://volatility-labs.blogspot.com/2018/05/the-6th-annual-volatility-plugin.html)
- 2018.05 [pentestingexperts] [Memory Forensics Investigation using Volatility (Part 1)](http://www.pentestingexperts.com/memory-forensics-investigation-using-volatility-part-1/)
- 2018.05 [cybertriage] [Using Volatility in Cyber Triage to Analyze Memory](https://www.cybertriage.com/2018/using-volatility-in-cyber-triage/)
- 2018.04 [acolyer] [Espresso: brewing Java for more non-volatility with non-volatile memory](https://blog.acolyer.org/2018/04/25/espresso-brewing-java-for-more-non-volatility-with-non-volatile-memory/)
- 2018.03 [broadanalysis] [Guest Blog Post: njRat Analysis with Volatility](http://www.broadanalysis.com/2018/03/25/guest-blog-post-njrat-analysis-with-volatility/)
- 2018.03 [X13Cubed] [Volatility Profiles and Windows 10](https://www.youtube.com/watch?v=Us1gbPqtdtY)
- 2018.01 [cydefe] [Tools 101: Volatility Usage](http://www.cydefe.com/podcast/2018/1/30/tools-101-volatility-usage)
- 2018.01 [hackingarticles] [Memory Forensics Investigation using Volatility (Part 1)](http://www.hackingarticles.in/memory-forensics-investigation-using-volatility-part-1/)
- 2017.12 [360] [如何使用QEMU和Volatility攻击全盘加密的系统](https://www.anquanke.com/post/id/90794/)
- 2017.12 [diablohorn] [attacking encrypted systems with qemu and volatility](https://diablohorn.com/2017/12/12/attacking-encrypted-systems-with-qemu-and-volatility/)
- 2017.11 [pentestingexperts] [Stuxnet’s Footprint in Memory with Volatility 2.0](http://www.pentestingexperts.com/stuxnets-footprint-in-memory-with-volatility-2-0/)
- 2017.11 [volatility] [Results from the (5th Annual) 2017 Volatility Plugin Contest are in!](https://volatility-labs.blogspot.com/2017/11/results-from-5th-annual-2017-volatility.html)
- 2017.10 [sans] [Using Yara rules with Volatility ](https://isc.sans.edu/forums/diary/Using+Yara+rules+with+Volatility/22950/)
- 2017.10 [4hou] [使用Volatility检测DoublePulsar](http://www.4hou.com/system/7321.html)
- 2017.08 [shelliscoming] [DoublePulsar SMB implant detection from Volatility](http://www.shelliscoming.com/2017/08/doublepulsar-smb-implant-detection-from.html)
- 2017.08 [nextplatform] [The Ironic – And Fleeting – Volatility In NVM Storage](https://www.nextplatform.com/2017/08/14/ironic-fleeting-volatility-nvm-storage/)
- 2017.05 [360] [电子取证技术之实战Volatility工具](https://www.anquanke.com/post/id/86036/)
- 2017.04 [volatility] [The (5th Annual) 2017 Volatility Plugin Contest is Live!](https://volatility-labs.blogspot.com/2017/04/the-5th-annual-2017-volatility-plugin.html)
- 2017.02 [ponderthebits] [OSX (Mac) Memory Acquisition and Analysis Using OSXpmem and Volatility](http://ponderthebits.com/2017/02/osx-mac-memory-acquisition-and-analysis-using-osxpmem-and-volatility/)
- 2017.01 [freebuf] [利用Volatility进行Windows内存取证分析(二)：内核对象、内核池学习小记](http://www.freebuf.com/sectool/124800.html)
- 2017.01 [freebuf] [利用Volatility进行Windows内存取证分析(一)：初体验](http://www.freebuf.com/sectool/124690.html)
- 2016.12 [volatility] [The Release of Volatility 2.6](https://volatility-labs.blogspot.com/2016/12/the-release-of-volatility-26.html)
- 2016.12 [volatility] [Results from the 2016 Volatility Plugin Contest are in!](https://volatility-labs.blogspot.com/2016/12/results-from-2016-volatility-plugin.html)
- 2016.10 [sans] [Volatility Bot: Automated Memory Analysis](https://isc.sans.edu/forums/diary/Volatility+Bot+Automated+Memory+Analysis/21655/)
- 2016.10 [tisiphone] [Using Team Cymru’s MHR with Volatility](https://tisiphone.net/2016/10/27/using-team-cymrus-mhr-with-volatility/)
- 2016.10 [n0where] [Automated Memory Analyzer For Malware Samples: VolatilityBot](https://n0where.net/automated-memory-analyzer-volatilitybot)
- 2016.09 [volatility] [Volatility Update: Core team is growing!](https://volatility-labs.blogspot.com/2016/09/volatility-update-core-team-is-growing.html)
- 2016.09 [cysinfo] [Detecting Malicious Processes Using Psinfo Volatility Plugin](https://cysinfo.com/detecting-malicious-processes-psinfo-volatility-plugin/)
- 2016.09 [cysinfo] [Detecting Deceptive Process Hollowing Techniques Using HollowFind Volatility Plugin](https://cysinfo.com/detecting-deceptive-hollowing-techniques/)
- 2016.08 [linoxide] [How to Setup Volatility Tool for Memory Analysis](https://linoxide.com/linux-how-to/setup-volatility-memory-analysis/)
- 2016.07 [cysinfo] [Linux Memory Diff Analysis using Volatility](https://cysinfo.com/linux-memory-diff-analysis-using-volatility-2/)
- 2016.06 [cysinfo] [Hunting APT RAT 9002 In Memory Using Volatility Plugin](https://cysinfo.com/hunting-apt-rat-9002-in-memory-using-volatility-plugin/)
- 2016.05 [freebuf] [使用VOLATILITY发现高级恶意软件](http://www.freebuf.com/articles/system/104899.html)
- 2016.04 [virusbulletin] [VB2015 paper: VolatilityBot: Malicious Code Extraction Made by and for Security Researchers](https://www.virusbulletin.com/blog/2016/02/vb2015-paper-volatilitybot-malicious-code-extraction-made-and-security-researchers/)
- 2016.04 [holisticinfosec] [toolsmith #115: Volatility Acuity with VolUtility](https://holisticinfosec.blogspot.com/2016/04/toolsmith-115-volatility-acuity-with.html)
- 2016.04 [volatility] [Airbnb Donates $999 to the 2016 Volatility Plugin Contest!](https://volatility-labs.blogspot.com/2016/04/airbnb-donates-999-to-2016-volatility.html)
- 2016.04 [volatility] [The 2016 Volatility Plugin Contest is now live!](https://volatility-labs.blogspot.com/2016/04/the-2016-volatility-plugin-contest-is.html)
- 2016.02 [360] [在windows环境下使用Volatility或PE Capture捕捉执行代码（PE/DLL/驱动恶意文件）](https://www.anquanke.com/post/id/83507/)
- 2016.02 [tribalchicken] [Extracting FileVault 2 Keys with Volatility](https://tribalchicken.io/extracting-filevault-2-keys-with-volatility/)
- 2016.02 [tribalchicken] [Extracting FileVault 2 Keys with Volatility](https://tribalchicken.net/extracting-filevault-2-keys-with-volatility/)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Overview](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-overview/)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Part 1: Mimikatz & lsass.exe Dump](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-1-mimikatz-lsass-exe-dump/)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Part 2: Windows 7 Full Memory Dump & Get Hashes](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-2-windows-7-full-memory-dump-get-hashes/)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Part 3: WinDBG Mimikatz Extension](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-3-windbg-mimikatz-extension/)
- 2016.02 [govolution] [Windows Credentials and Memory Dumps – Part 4: Volatility & Mimikatz](https://govolution.wordpress.com/2016/02/06/windows-credentials-and-memory-dumps-part-4-volatility-mimikatz/)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Part 6: VMWare Workstation](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-6-vmware-workstation/)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Part 7: ESXi Server](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-7-esxi-server/)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Part 8: ESXi Attacking Scenario – Volatility on ESXi](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-8-esxi-attacking-scenario-volatility-on-esxi/)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Part 9: Logging & Monitoring ESXi](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-9-logging-monitoring-esxi/)
- 2016.01 [sans] [Some useful volatility plugins ](https://isc.sans.edu/forums/diary/Some+useful+volatility+plugins/20623/)
- 2016.01 [metabrik] [Malware analysis with VM instrumentation, WMI, winexe, Volatility and Metabrik](https://www.metabrik.org/blog/2016/01/09/malware-analysis-with-vm-instrumentation-wmi-winexe-volatility-and-metabrik/)
- 2015.11 [volatility] [Guest Post: Martin Korman (VolatilityBot - An Automated Malicious Code Dumper)](https://volatility-labs.blogspot.com/2015/11/guest-post-martin-korman-volatilitybot.html)
- 2015.11 [tribalchicken] [Extracting BitLocker keys with Volatility (PoC)](https://tribalchicken.io/extracting-bitlocker-keys-with-volatility-part-1-poc/)
- 2015.11 [tribalchicken] [Extracting BitLocker keys with Volatility (PoC)](https://tribalchicken.net/extracting-bitlocker-keys-with-volatility-part-1-poc/)
- 2015.11 [secist] [调查取证之Volatility框架的使用](http://www.secist.com/archives/2082.html)
- 2015.11 [n0where] [Volatile Memory Extraction: The Volatility Framework](https://n0where.net/volatile-memory-extraction)
- 2015.11 [volatility] [PlugX: Memory Forensics Lifecycle with Volatility](https://volatility-labs.blogspot.com/2015/11/plugx-memory-forensics-lifecycle-with.html)
- 2015.10 [volatility] [Results from the 2015 Volatility Plugin Contest are in!](https://volatility-labs.blogspot.com/2015/10/results-from-2015-volatility-plugin.html)
- 2015.10 [autopsy] [The Volatility team talks proactive threat hunting with memory forensics (an OSDFCon presentation)](https://www.autopsy.com/the-volatility-team-talks-proactive-threat-hunting-with-memory-forensics-an-osdfcon-presentation/)
- 2015.10 [angelalonso] [Android Memory Analysis (II) - Extracting the memory and analyzing with Volatility](http://blog.angelalonso.es/2015/10/android-memory-analysis-analyzing.html)
- 2015.09 [airbuscybersecurity] [Volatility plugin for PlugX updated](http://blog.airbuscybersecurity.com/post/2015/08/Volatility-plugin-for-PlugX-updated)
- 2015.08 [volatility] [Volatility Updates Summer 2015](https://volatility-labs.blogspot.com/2015/08/volatility-updates-summer-2015.html)
- 2015.07 [volatility] [The 2015 Volatility Plugin contest is now live!](https://volatility-labs.blogspot.com/2015/07/the-2015-volatility-plugin-contest-is.html)
- 2015.07 [volatility] [Volatility at Black Hat USA & DFRWS 2015!](https://volatility-labs.blogspot.com/2015/07/volatility-at-black-hat-usa-dfrws-2015.html)
- 2015.02 [kudelskisecurity] [Volatility plugin for Dyre](https://research.kudelskisecurity.com/2015/02/11/volatility-plugin-for-dyre/)
- 2014.12 [sans] [Some Memory Forensic with Forensic Suite (Volatility plugins)](https://isc.sans.edu/forums/diary/Some+Memory+Forensic+with+Forensic+Suite+Volatility+plugins/19071/)
- 2014.10 [volatility] [Announcing the 2014 Volatility Plugin Contest Results!](https://volatility-labs.blogspot.com/2014/10/announcing-2014-volatility-plugin.html)
- 2014.09 [volatility] [The Volatility Foundation: Fighting for Open Source Forensics](https://volatility-labs.blogspot.com/2014/09/the-volatility-foundation-fighting-for.html)
- 2014.09 [volatility] [Volatility 2.4 at Blackhat Arsenal - Defeating Truecrypt Disk Encryption](https://volatility-labs.blogspot.com/2014/09/volatility-24-at-blackhat-arsenal.html)
- 2014.09 [volatility] [Facebook Donation Doubles the Volatility Plugin Contest Prizes](https://volatility-labs.blogspot.com/2014/09/facebook-donation-doubles-volatility.html)
- 2014.09 [volatility] [Heads Up! 2014 Volatility Plugin Contest Deadline Extended!](https://volatility-labs.blogspot.com/2014/09/heads-up-2014-volatility-plugin-contest.html)
- 2014.08 [volatility] [Volatility 2.4 at Blackhat Arsenal - Reverse Engineering Rootkits](https://volatility-labs.blogspot.com/2014/08/volatility-24-at-blackhat-arsenal.html)
- 2014.08 [] [Forensic FOSS: 4n6k_volatility_installer.sh - Install Volatility For Linux Automatically](http://www.4n6k.com/2014/08/forensic-foss-4n6kvolatilityinstallersh.html)
- 2014.08 [volatility] [Volatility 2.4 at Blackhat Arsenal - Tracking Mac OS X User Activity](https://volatility-labs.blogspot.com/2014/08/volatility-24-at-blackhat-arsenal_21.html)
- 2014.08 [toolswatch] [Volatility v2.4 – Art of Memory Forensics Released](http://www.toolswatch.org/2014/08/volatility-v2-4-art-of-memory-forensics-released/)
- 2014.08 [volatility] [New Volatility 2.4 Cheet Sheet with Linux, Mac, and RTFM](https://volatility-labs.blogspot.com/2014/08/new-volatility-24-cheet-sheet-with.html)
- 2014.08 [volatility] [Presenting Volatility Foundation Volatility Framework 2.4](https://volatility-labs.blogspot.com/2014/08/presenting-volatility-foundation.html)
- 2014.07 [volatility] [Volatility at Black Hat USA & DFRWS 2014](https://volatility-labs.blogspot.com/2014/07/volatility-at-black-hat-usa-dfrws-2014.html)
- 2014.05 [volatility] [Volatility - Update All The Things](https://volatility-labs.blogspot.com/2014/05/volatility-update-all-things.html)
- 2014.04 [volatility] [Volatility Memory Forensics and Malware Analysis Training in Australia!](https://volatility-labs.blogspot.com/2014/04/volatility-memory-forensics-and-malware.html)
- 2014.03 [reverse] [Teaching Rex another TrustedBSD trick to hide from Volatility](https://reverse.put.as/2014/03/18/teaching-rex-another-trustedbsd-trick-to-hide-from-volatility/)
- 2014.03 [mcafee] [Timeline of Bitcoin Events Demonstrates Online Currency’s Volatility](https://securingtomorrow.mcafee.com/mcafee-labs/timeline-bitcoin-events-demonstrates-volatility/)
- 2014.02 [freebuf] [利用Volatility查找系统中的恶意DLL](http://www.freebuf.com/articles/system/26936.html)
- 2014.02 [freebuf] [Linux下内存取证工具Volatility的使用](http://www.freebuf.com/articles/system/26763.html)
- 2014.02 [volatility] [Training by The Volatility Project Now Available In Three Continents!](https://volatility-labs.blogspot.com/2014/02/training-by-volatility-project-now.html)
- 2013.11 [holisticinfosec] [Volatility 2.3 and FireEye's diskless, memory-only Trojan.APT.9002](https://holisticinfosec.blogspot.com/2013/11/volatility-23-and-fireeyes-diskless.html)
- 2013.11 [toolswatch] [Volatility The advanced memory forensics framework v2.3 available (Support of OSX)](http://www.toolswatch.org/2013/11/volatility-the-advanced-memory-forensics-framework-v2-3-available-support-of-osx/)
- 2013.10 [volatility] [Volatility 2.3 Released! (Official Mac OS X and Android Support)](https://volatility-labs.blogspot.com/2013/10/volatility-23-released-official-mac-os.html)
- 2013.09 [volatility] [Leveraging CybOX with Volatility](https://volatility-labs.blogspot.com/2013/09/leveraging-cybox-with-volatility.html)
- 2013.08 [quequero] [Quick Volatility overview and R.E. analysis of Win32.Chebri](https://quequero.org/2013/08/quick-volatility-overview-and-r-e-analysis-of-win32-chebri/)
- 2013.08 [volatility] [Results are in for the 1st Annual Volatility Framework Plugin Contest!](https://volatility-labs.blogspot.com/2013/08/results-are-in-for-1st-annual.html)
- 2013.06 [sans] [Volatility rules...any questions?](https://isc.sans.edu/forums/diary/Volatility+rulesany+questions/16022/)
- 2013.06 [volatility] [MOVP II - 4.5 - Mac Volatility vs the Rubilyn Kernel Rootkit](https://volatility-labs.blogspot.com/2013/06/movp-ii-45-mac-volatility-vs-rubilyn.html)
- 2013.05 [volatility] [Automated Volatility Plugin Generation with Dalvik Inspector](https://volatility-labs.blogspot.com/2013/05/automated-volatility-plugin-generation.html)
- 2013.05 [securityintelligence] [Zeus Analysis – Memory Forensics via Volatility](https://securityintelligence.com/zeus-analysis-memory-forensics-via-volatility/)
- 2013.05 [volatility] [MoVP II - 2.3 - Creating Timelines with Volatility](https://volatility-labs.blogspot.com/2013/05/movp-ii-23-creating-timelines-with.html)
- 2013.05 [volatility] [MOVP II - 1.5 - ARM Address Space (Volatility and Android / Mobile)](https://volatility-labs.blogspot.com/2013/05/movp-ii-15-arm-address-space-volatility.html)
- 2013.05 [volatility] [What's Happening in the World of Volatility?](https://volatility-labs.blogspot.com/2013/05/whats-happening-in-world-of-volatility.html)
- 2013.04 [cyberarms] [Volatility Memory Analysis Article Featured in eForensics Magazine](https://cyberarms.wordpress.com/2013/04/02/volatility-memory-analysis-article-featured-in-eforensics-magazine/)
- 2013.03 [volatility] [Official Training by Volatility - Reston/VA, June 2013](https://volatility-labs.blogspot.com/2013/03/official-training-by-volatility.html)
- 2013.01 [theevilbit] [Backtrack Forensics: Memory analysis with volatility](http://theevilbit.blogspot.com/2013/01/backtrack-forensics-memory-analysis.html)
- 2013.01 [volatility] [The 1st Annual Volatility Framework Plugin Contest](https://volatility-labs.blogspot.com/2013/01/the-1st-annual-volatility-framework.html)
- 2013.01 [hackingarticles] [Volatility – An advanced memory forensics framework](http://www.hackingarticles.in/volatility-an-advanced-memory-forensics-framework/)
- 2012.12 [volatility] [What do Upclicker, Poison Ivy, Cuckoo, and Volatility Have in Common?](https://volatility-labs.blogspot.com/2012/12/what-do-upclicker-poison-ivy-cuckoo-and.html)
- 2012.12 [securityartwork] [New MFTParser plugin in the alpha version of Volatility](https://www.securityartwork.es/2012/12/18/new-mftparser-plugin-in-the-alpha-version-of-volatility/)
- 2012.11 [volatility] [Windows Memory Forensics Training for Analysts by Volatility Developers](https://volatility-labs.blogspot.com/2012/11/windows-memory-forensics-training-for.html)
- 2012.10 [volatility] [OMFW 2012: Analyzing Linux Kernel Rootkits with Volatility](https://volatility-labs.blogspot.com/2012/10/omfw-2012-analyzing-linux-kernel.html)
- 2012.10 [volatility] [MoVP for Volatility 2.2 and OMFW 2012 Wrap-Up](https://volatility-labs.blogspot.com/2012/10/movp-for-volatility-22-and-omfw-2012.html)
- 2012.10 [volatility] [Solving the GrrCon Network Forensics Challenge with Volatility](https://volatility-labs.blogspot.com/2012/10/solving-grrcon-network-forensics.html)
- 2012.10 [volatility] [Phalanx 2 Revealed: Using Volatility to Analyze an Advanced Linux Rootkit](https://volatility-labs.blogspot.com/2012/10/phalanx-2-revealed-using-volatility-to.html)
- 2012.09 [volatility] [MoVP 3.5: Analyzing the 2008 DFRWS Challenge with Volatility](https://volatility-labs.blogspot.com/2012/09/movp-35-analyzing-2008-dfrws-challenge.html)
- 2012.09 [volatility] [MoVP 2.5: Investigating In-Memory Network Data with Volatility](https://volatility-labs.blogspot.com/2012/09/movp-25-investigating-in-memory-network.html)
- 2012.09 [sans] [Volatility: 2.2 is Coming Soon](https://isc.sans.edu/forums/diary/Volatility+22+is+Coming+Soon/14125/)
- 2012.09 [volatility] [Month of Volatility Plugins (MoVP)](https://volatility-labs.blogspot.com/2012/09/month-of-volatility-plugins-movp.html)
- 2012.08 [sans] [Digital Forensics Case Leads: Identifying TrueCrypt volumes with Volatility, Malware that can sneak into VM's and more....](https://digital-forensics.sans.org/blog/2012/08/24/digital-forensics-case-leads-identifying-truecrypt-volumes-with-volatility-malware-that-can-sneak-into-vms-and-more)
- 2012.08 [sans] [Digital Forensics Case Leads: Multi-plat RAT, No US Cybersecurity bill, Dropbox drops a doozie, Volatility everywhere](https://digital-forensics.sans.org/blog/2012/08/03/digital-forensics-case-leads-multi-plat-rat-no-us-cybersecurity-bill-dropbox-drops-a-doozie-volatility-everywhere)
- 2012.07 [sans] [Digital Forensics Case Leads: Skype acting weird, Mircosoft backdooring Skype! Volatility with x64 support... Facebook censoring chats for criminal activities!? A Russian hacker challenge Apple by bypassing Apple Store authentication mechanism and get apps for free!!! All that and more, this week on Case Leadsâ¦](https://digital-forensics.sans.org/blog/2012/07/21/digital-forensics-case-leads-skype-acting-weird-mircosoft-backdooring-skype-volatility-with-x64-support-facebook-censoring-chats-for-criminal-activities-a-russian-hacker-challenge-apple-by-byp)
- 2012.04 [hiddenillusion] [YARA + Volatility ... the beginning](http://hiddenillusion.blogspot.com/2012/04/yara-volatility-beginning.html)
- 2012.03 [hiddenillusion] [Making Volatility work for you](http://hiddenillusion.blogspot.com/2012/03/making-volatility-work-for-you.html)
- 2011.10 [quequero] [Shylock via volatility](https://quequero.org/2011/10/shylock-via-volatility/)
- 2011.09 [holisticinfosec] [toolsmith: Memory Analysis with DumpIt and Volatility](https://holisticinfosec.blogspot.com/2011/09/toolsmith-memory-analysis-with-dumpit.html)
- 2011.08 [sans] [Digital Forensics Case Leads: SIFT 2.1, Volatility 2.0](https://digital-forensics.sans.org/blog/2011/08/04/digital-forensics-case-leads-8-4-11)
- 2011.02 [toolswatch] [Volatility The advanced memory forensics framework v1.4 released](http://www.toolswatch.org/2011/02/volatility-the-advanced-memory-forensics-framework-v1-4-released/)
- 2011.01 [sans] [A Quick Look at Volatility 1.4 RC1 - What's New?](https://digital-forensics.sans.org/blog/2011/01/13/whats-new-volatility-1-4)
- 2010.05 [holisticinfosec] [Memory forensics with SIFT 2.0, Volatility, and PTK](https://holisticinfosec.blogspot.com/2010/05/memory-forensics-with-sift-20.html)
- 2010.02 [sans] [Digital Forensics Case Leads: Volatility and RegRipper, Better Together](https://digital-forensics.sans.org/blog/2010/02/18/digital-forensics-case-leads-volatility-and-regripper-better-together)
- 2009.07 [sans] [New Volatility plugins](https://isc.sans.edu/forums/diary/New+Volatility+plugins/6862/)
- 2009.05 [sans] [More new volatility plugins](https://isc.sans.edu/forums/diary/More+new+volatility+plugins/6475/)
- 2009.04 [windowsir] [New Volatility Plugins](http://windowsir.blogspot.com/2009/04/new-volatility-plugins.html)
- 2009.03 [moyix] [Using Volatility for Introspection](http://moyix.blogspot.com/2009/03/using-volatility-for-introspection.html)
- 2009.03 [moyix] [RegRipper and Volatility Prototype](http://moyix.blogspot.com/2009/03/regripper-and-volatility-prototype.html)
- 2008.08 [windowsir] [Volatility 1.3 is out!](http://windowsir.blogspot.com/2008/08/volatility-13-is-out.html)
- 2008.08 [moyix] [Volatility 1.3 is out!](http://moyix.blogspot.com/2008/08/volatility-13-is-out.html)


***


## <a id="c529f60a5b6f420255ae79843446a145"></a>Sleuthkit


- 2018.10 [insinuator] [Comparison of our tool afro (APFS file recovery) with Blackbag Blacklight and Sleuthkit](https://insinuator.net/2018/10/comparison-of-our-tool-afro-apfs-file-recovery-with-blackbag-blacklight-and-sleuthkit/)
- 2011.10 [sans] [Digital Forensics Case Leads:  Passwords in Wills, Google Chrome a Virus, Cybercrime Unit Saving Money and Updates for Sleuthkit and SSDeep.](https://digital-forensics.sans.org/blog/2011/10/14/digital-forensics-case-leads-passwords-in-wills-google-chrome-a-virus-cybercrime-unit-saving-money-and-updates-for-sleuthkit-and-ssdeep)
- 2011.09 [sans] [Shadow Timelines And Other VolumeShadowCopy Digital Forensics Techniques with the Sleuthkit on Windows](https://digital-forensics.sans.org/blog/2011/09/16/shadow-timelines-and-other-shadowvolumecopy-digital-forensics-techniques-with-the-sleuthkit-on-windows)
- 2005.10 [windowsir] [Sleuthkit on Windows](http://windowsir.blogspot.com/2005/10/sleuthkit-on-windows.html)


***


## <a id="b6797fda3a16667cd5726ef4aa86b0e1"></a>Rekall


- 2019.01 [4hou] [借助Rekall进行内存实时分析](http://www.4hou.com/technology/15483.html)
- 2019.01 [sans] [Rekall Memory Forensics](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1493740529.pdf)
- 2018.12 [ironcastle] [Live memory analysis using Rekall, (Tue, Dec 25th)](https://www.ironcastle.net/live-memory-analysis-using-rekall-tue-dec-25th/)
- 2018.12 [sans] [Live memory analysis using Rekall](https://isc.sans.edu/forums/diary/Live+memory+analysis+using+Rekall/24454/)
- 2018.01 [rekall] [ELF hacking with Rekall](http://blog.rekall-forensic.com/2018/01/elf-hacking-with-rekall.html)
- 2017.08 [rekall] [Rekall Agent Alpha launch](http://blog.rekall-forensic.com/2017/08/rekall-agent-alpha-launch.html)
- 2017.07 [insinuator] [Release of Glibc Heap Analysis Plugins for Rekall](https://insinuator.net/2017/07/release-of-glibc-heap-analysis-plugins-for-rekall/)
- 2016.10 [rekall] [The Rekall Agent Whitepaper](http://blog.rekall-forensic.com/2016/10/the-rekall-agent-whitepaper.html)
- 2015.11 [toolswatch] [Rekall The Memory Forensic Framework](http://www.toolswatch.org/2015/11/rekall-the-memory-forensic-framework/)
- 2015.10 [holisticinfosec] [toolsmith #109: CapLoader network carving from Rekall WinPmem Memory Image](https://holisticinfosec.blogspot.com/2015/10/toolsmith-109-caploader-network-carving.html)
- 2015.05 [holisticinfosec] [toolsmith: Attack & Detection: Hunting in-memory adversaries with Rekall and WinPmem](https://holisticinfosec.blogspot.com/2015/05/toolsmith-attack-detection-hunting-in.html)
- 2015.02 [n0where] [Rekall Memory Forensic Framework](https://n0where.net/rekall-memory-forensic-framework)
- 2014.03 [sans] [Linux Memory Dump with Rekall](https://isc.sans.edu/forums/diary/Linux+Memory+Dump+with+Rekall/17775/)


# <a id="d4e014cbc478d3e5625e6ca1622781d3"></a>Tools


***


## <a id="ecb63dfb62722feb6d43a9506515b4e3"></a>Recent Add


- [**5208**Star][7m] [Py] [usarmyresearchlab/dshell](https://github.com/usarmyresearchlab/dshell) Dshell is a network forensic analysis framework.
- [**3337**Star][11d] [Py] [google/grr](https://github.com/google/grr) remote live forensics for incident response
- [**1912**Star][13d] [Shell] [toniblyx/prowler](https://github.com/toniblyx/prowler) AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool. It follows guidelines of the CIS Amazon Web Services Foundations Benchmark and DOZENS of additional checks including GDPR and HIPAA (+100). Official CIS for AWS guide:
- [**1227**Star][12d] [Py] [google/timesketch](https://github.com/google/timesketch) Collaborative forensic timeline analysis
- [**1155**Star][4m] [Go] [mozilla/mig](https://github.com/mozilla/mig) Distributed & real time digital forensics at the speed of the cloud
- [**1024**Star][13d] [Py] [ondyari/faceforensics](https://github.com/ondyari/faceforensics) Github of the FaceForensics dataset
- [**1017**Star][12d] [Rich Text Format] [decalage2/oletools](https://github.com/decalage2/oletools)  python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging.
- [**949**Star][2y] [C#] [invoke-ir/powerforensics](https://github.com/invoke-ir/powerforensics) PowerForensics provides an all in one platform for live disk forensic analysis
- [**883**Star][2m] [C] [cisco/joy](https://github.com/cisco/joy) A package for capturing and analyzing network flow data and intraflow data, for network research, forensics, and security monitoring.
- [**832**Star][27d] [Py] [yampelo/beagle](https://github.com/yampelo/beagle)  an incident response and digital forensics tool which transforms security logs and data into graphs.
- [**791**Star][4m] [Py] [srinivas11789/pcapxray](https://github.com/srinivas11789/pcapxray) visualize a Packet Capture offline as a Network Diagram including device identification, highlight important communication and file extraction
- [**762**Star][2m] [Py] [snovvcrash/usbrip](https://github.com/snovvcrash/usbrip) Simple CLI forensics tool for tracking USB device artifacts (history of USB events) on GNU/Linux
- [**544**Star][1m] [Go] [biggiesmallsag/nighthawkresponse](https://github.com/biggiesmallsag/nighthawkresponse) Incident Response Forensic Framework
- [**485**Star][26d] [Py] [netflix-skunkworks/diffy](https://github.com/netflix-skunkworks/diffy) a triage tool used during cloud-centric security incidents, to help digital forensics and incident response (DFIR) teams quickly identify suspicious hosts on which to focus their response.
- [**429**Star][3m] [Py] [obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight) Internet history forensics for Google Chrome/Chromium
- [**419**Star][20d] [Py] [forensicartifacts/artifacts](https://github.com/forensicartifacts/artifacts) Digital Forensics Artifact Repository
- [**395**Star][2y] [PS] [cryps1s/darksurgeon](https://github.com/cryps1s/darksurgeon) a Windows packer project to empower incident response, digital forensics, malware analysis, and network defense.
- [**392**Star][11m] [Go] [mozilla/masche](https://github.com/mozilla/masche) MIG Memory Forensic library
- [**381**Star][5y] [JS] [le4f/pcap-analyzer](https://github.com/le4f/pcap-analyzer) online pcap forensic
- [**349**Star][3m] [Shell] [orlikoski/skadi](https://github.com/orlikoski/Skadi) collection, processing and advanced analysis of forensic artifacts and images.
- [**324**Star][11m] [Py] [alessandroz/lazagneforensic](https://github.com/alessandroz/lazagneforensic) Windows passwords decryption from dump files
- [**320**Star][2y] [C] [fireeye/rvmi](https://github.com/fireeye/rvmi) A New Paradigm For Full System Analysis
- [**316**Star][12d] [Py] [google/turbinia](https://github.com/google/turbinia) Automation and Scaling of Digital Forensics Tools
- [**303**Star][2m] [Shell] [vitaly-kamluk/bitscout](https://github.com/vitaly-kamluk/bitscout) Remote forensics meta tool
- [**295**Star][3y] [invoke-ir/forensicposters](https://github.com/invoke-ir/forensicposters) 多种数据结构图解：MBR/GPT/...
- [**274**Star][13d] [Perl] [owasp/o-saft](https://github.com/owasp/o-saft) OWASP SSL advanced forensic tool
- [**268**Star][3y] [Py] [ghirensics/ghiro](https://github.com/ghirensics/ghiro) Automated image forensics tool
- [**263**Star][7m] [Batchfile] [diogo-fernan/ir-rescue](https://github.com/diogo-fernan/ir-rescue) A Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
- [**260**Star][1m] [Py] [google/docker-explorer](https://github.com/google/docker-explorer) A tool to help forensicate offline docker acquisitions
- [**252**Star][1y] [C++] [comaeio/swishdbgext](https://github.com/comaeio/SwishDbgExt) Incident Response & Digital Forensics Debugging Extension
- [**247**Star][1m] [Py] [orlikoski/cdqr](https://github.com/orlikoski/CDQR) a fast and easy to use forensic artifact parsing tool that works on disk images, mounted drives and extracted artifacts from Windows, Linux, MacOS, and Android devices
- [**245**Star][1y] [Py] [crowdstrike/forensics](https://github.com/crowdstrike/forensics) Scripts and code referenced in CrowdStrike blog posts
- [**233**Star][2m] [C] [elfmaster/libelfmaster](https://github.com/elfmaster/libelfmaster) Secure ELF parsing/loading library for forensics reconstruction of malware, and robust reverse engineering tools
- [**225**Star][3m] [Py] [crowdstrike/automactc](https://github.com/crowdstrike/automactc) Automated Mac Forensic Triage Collector
- [**224**Star][4y] [Java] [nowsecure/android-forensics](https://github.com/nowsecure/android-forensics) Open source Android Forensics app and framework
- [**213**Star][2y] [C#] [shanek2/invtero.net](https://github.com/shanek2/invtero.net) A high speed (Gbps) Forensics, Memory integrity & assurance. Includes offensive & defensive memory capabilities. Find/Extract processes, hypervisors (including nested) in memory dumps using microarchitechture independent Virtual Machiene Introspection techniques
- [**202**Star][11m] [Py] [medbenali/cyberscan](https://github.com/medbenali/cyberscan) Network's Forensics ToolKit
- [**191**Star][2m] [Py] [lazza/recuperabit](https://github.com/lazza/recuperabit) A tool for forensic file system reconstruction.
- [**177**Star][11d] [Py] [markbaggett/srum-dump](https://github.com/markbaggett/srum-dump) A forensics tool to convert the data in the Windows srum (System Resource Usage Monitor) database to an xlsx spreadsheet.
- [**176**Star][4y] [Py] [csababarta/ntdsxtract](https://github.com/csababarta/ntdsxtract) Active Directory forensic framework
- [**168**Star][2y] [Py] [monrocoury/forensic-tools](https://github.com/monrocoury/forensic-tools) A collection of tools for forensic analysis
- [**162**Star][6m] [Py] [cvandeplas/elk-forensics](https://github.com/cvandeplas/elk-forensics) ELK configuration files for Forensic Analysts and Incident Handlers (unmaintained)
- [**162**Star][2m] [C++] [gregwar/fatcat](https://github.com/gregwar/fatcat) FAT filesystems explore, extract, repair, and forensic tool
- [**158**Star][2m] [Py] [travisfoley/dfirtriage](https://github.com/travisfoley/dfirtriage) Digital forensic acquisition tool for Windows based incident response.
- [**154**Star][9m] [Py] [vikwin/pcapfex](https://github.com/vikwin/pcapfex) 'Packet Capture Forensic Evidence eXtractor' is a tool that finds and extracts files from packet capture files
- [**150**Star][4m] [Py] [stuhli/dfirtrack](https://github.com/stuhli/dfirtrack) The Incident Response Tracking Application
- [**149**Star][4y] [Py] [arxsys/dff](https://github.com/arxsys/dff) a Forensics Framework coming with command line and graphical interfaces. 
- [**146**Star][2y] [Py] [davidpany/wmi_forensics](https://github.com/davidpany/wmi_forensics)  scripts used to find evidence in WMI repositories, specifically OBJECTS.DATA files
- [**141**Star][2m] [C++] [dfir-orc/dfir-orc](https://github.com/dfir-orc/dfir-orc) Forensics artefact collection tool for systems running Microsoft Windows
- [**139**Star][2y] [Py] [jrbancel/chromagnon](https://github.com/jrbancel/chromagnon) Chrome/Chromium Forensic Tool : Parses History, Visited Links, Downloaded Files and Cache
- [**131**Star][2m] [Py] [benjeems/packetstrider](https://github.com/benjeems/packetstrider) A network packet forensics tool for SSH
- [**131**Star][2m] [Py] [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) Digital Forensics Virtual File System (dfVFS)
- [**123**Star][3y] [PS] [silverhack/voyeur](https://github.com/silverhack/voyeur)  generate a fast (and pretty) Active Directory report.
- [**122**Star][3m] [Py] [redaelli/imago-forensics](https://github.com/redaelli/imago-forensics) a python tool that extract digital evidences from images.
- [**119**Star][2y] [PS] [javelinnetworks/ir-tools](https://github.com/javelinnetworks/ir-tools)  forensics of domain based attacks on an infected host
- [**118**Star][13d] [Py] [domainaware/parsedmarc](https://github.com/domainaware/parsedmarc) A Python package and CLI for parsing aggregate and forensic DMARC reports
- [**115**Star][1y] [Shell] [theflakes/ultimate-forensics-vm](https://github.com/theflakes/ultimate-forensics-vm) Evolving directions on building the best Open Source Forensics VM
- [**113**Star][1y] [C#] [damonmohammadbagher/meterpreter_payload_detection](https://github.com/damonmohammadbagher/meterpreter_payload_detection) Meterpreter_Payload_Detection.exe tool for detecting Meterpreter in memory like IPS-IDS and Forensics tool
- [**112**Star][8m] [PHP] [xplico/xplico](https://github.com/xplico/xplico) Open Source Network Forensic Analysis Tool (NFAT)
- [**108**Star][5y] [Py] [mspreitz/adel](https://github.com/mspreitz/adel) dumps all important SQLite Databases from a connected Android smartphone to the local disk and analyzes these files in a forensically accurate workflow
- [**108**Star][3y] [projectretroscope/retroscope](https://github.com/projectretroscope/retroscope) Public release of the RetroScope Android memory forensics framework
- [**99**Star][2y] [Py] [trendmicro/defplorex](https://github.com/trendmicro/defplorex) defplorex for BlackHat Arsenal
- [**98**Star][6y] [Py] [matonis/page_brute](https://github.com/matonis/page_brute)  a digital forensic tool purposed to analyze and categorize individual paged memory frames from Windows Page Files by appying YARA-based signatures to fix-sized blocks of pagefile.sys
- [**97**Star][5m] [Py] [woanware/usbdeviceforensics](https://github.com/woanware/usbdeviceforensics) Python script for extracting USB information from Windows registry hives
- [**96**Star][1m] [Py] [airbus-cert/regrippy](https://github.com/airbus-cert/regrippy)  a framework for reading and extracting useful forensics data from Windows registry hives
- [**96**Star][2y] [JS] [anttikurittu/kirjuri](https://github.com/anttikurittu/kirjuri) a web application for managing cases and physical forensic evidence items.
- [**93**Star][20d] [Py] [log2timeline/dftimewolf](https://github.com/log2timeline/dftimewolf) A framework for orchestrating forensic collection, processing and data export
- [**88**Star][6m] [Go] [coinbase/dexter](https://github.com/coinbase/dexter) Forensics acquisition framework designed to be extensible and secure
- [**87**Star][2y] [C++] [google/aff4](https://github.com/google/aff4) The Advanced Forensic File Format
- [**86**Star][2y] [Py] [cheeky4n6monkey/4n6-scripts](https://github.com/cheeky4n6monkey/4n6-scripts) Forensic Scripts
- [**85**Star][6m] [Py] [quantika14/guasap-whatsapp-foresincs-tool](https://github.com/quantika14/guasap-whatsapp-foresincs-tool) WhatsApp Forensic Tool
- [**79**Star][3m] [Py] [google/giftstick](https://github.com/google/giftstick) 1-Click push forensics evidence to the cloud
- [**78**Star][3y] [C++] [jeffbryner/nbdserver](https://github.com/jeffbryner/nbdserver) Network Block Device Server for windows with a DFIR/forensic focus.
- [**78**Star][2y] [Py] [trolldbois/python-haystack](https://github.com/trolldbois/python-haystack) Process heap analysis framework - Windows/Linux - record type inference and forensics
- [**74**Star][2y] [Py] [busindre/dumpzilla](https://github.com/busindre/dumpzilla) Extract all forensic interesting information of Firefox, Iceweasel and Seamonkey browsers
- [**73**Star][2y] [C++] [kasperskylab/forensicstools](https://github.com/kasperskylab/forensicstools) Tools for DFIR
- [**64**Star][2y] [Py] [darkquasar/wmi_persistence](https://github.com/darkquasar/wmi_persistence) A repo to hold some scripts pertaining WMI (Windows implementation of WBEM) forensics
- [**64**Star][1y] [Py] [ralphje/imagemounter](https://github.com/ralphje/imagemounter) Command line utility and Python package to ease the (un)mounting of forensic disk images
- [**63**Star][3m] [C] [carmaa/interrogate](https://github.com/carmaa/interrogate)  a proof-of-concept tool for identification of cryptographic keys in binary material (regardless of target operating system), first and foremost for memory dump analysis and forensic usage.
- [**63**Star][2y] [Shell] [yukinoshita47/pentest-tools-auto-installer](https://github.com/yukinoshita47/pentest-tools-auto-installer) Tool sederhana buat install tool-tool pentest dan forensic bagi pengguna linux yang jenis nya non-pentest OS
- [**61**Star][4y] [Py] [sysinsider/usbtracker](https://github.com/sysinsider/usbtracker) Quick & dirty coded incident response and forensics python script to track USB devices events and artifacts in a Windows OS (Vista and later).
- [**53**Star][5y] [Py] [osandamalith/chromefreak](https://github.com/osandamalith/chromefreak) A Cross-Platform Forensic Framework for Google Chrome
- [**50**Star][10d] [PS] [s3cur3th1ssh1t/creds](https://github.com/S3cur3Th1sSh1t/Creds) Some usefull Scripts and Executables for Pentest & Forensics
- [**46**Star][3y] [PS] [n3l5/irfartpull](https://github.com/n3l5/irfartpull) PowerShell script utilized to pull several forensic artifacts from a live Win7 and WinXP system without WINRM.
- [**46**Star][1y] [Py] [sentenza/gimp-ela](https://github.com/sentenza/gimp-ela) A JPEG Error Level Analysis forensic plugin for the GNU Image Manipulation Program (GIMP)
- [**46**Star][8m] [YARA] [xumeiquer/yara-forensics](https://github.com/xumeiquer/yara-forensics) Set of Yara rules for finding files using magics headers
- [**43**Star][4m] [TSQL] [abrignoni/dfir-sql-query-repo](https://github.com/abrignoni/dfir-sql-query-repo) Collection of SQL query templates for digital forensics use by platform and application.
- [**43**Star][2y] [C#] [zacbrown/hiddentreasure-etw-demo](https://github.com/zacbrown/hiddentreasure-etw-demo) Basic demo for Hidden Treasure talk.
- [**42**Star][11d] [Py] [simsong/dfxml](https://github.com/simsong/dfxml) Digital Forensics XML project and library
- [**40**Star][2y] [HTML] [scorelab/androphsy](https://github.com/scorelab/androphsy) An Open Source Mobile Forensics Investigation Tool for Android Platform
- [**39**Star][4y] [AutoIt] [ajmartel/irtriage](https://github.com/ajmartel/irtriage) Incident Response Triage - Windows Evidence Collection for Forensic Analysis
- [**38**Star][2y] [C] [adulau/dcfldd](https://github.com/adulau/dcfldd) enhanced version of dd for forensics and security
- [**38**Star][2y] [Py] [ytisf/muninn](https://github.com/ytisf/muninn) A short and small memory forensics helper.
- [**37**Star][10m] [Py] [att/docker-forensics](https://github.com/att/docker-forensics) Tools to assist in forensicating docker
- [**36**Star][5y] [Py] [eurecom-s3/actaeon](https://github.com/eurecom-s3/actaeon) Memory forensics of virtualization environments
- [**35**Star][8m] [Py] [am0nt31r0/osint-search](https://github.com/am0nt31r0/osint-search) Useful for digital forensics investigations or initial black-box pentest footprinting.
- [**33**Star][2y] [C] [weaknetlabs/byteforce](https://github.com/weaknetlabs/byteforce) Offline Digital Forensics Tool for Binary Files
- [**32**Star][1y] [Py] [andreafortuna/autotimeliner](https://github.com/andreafortuna/autotimeliner) Automagically extract forensic timeline from volatile memory dump
- [**31**Star][7y] [Perl] [appliedsec/forensicscanner](https://github.com/appliedsec/forensicscanner) Forensic Scanner
- [**31**Star][2y] [Py] [bltsec/violent-python3](https://github.com/bltsec/violent-python3) Python 3 scripts based on lessons learned from Violent Python: A Cookbook for Hackers, Forensic Analysts, Penetration Testers and Security Engineers by TJ O'Connor.
- [**31**Star][5y] [Py] [madpowah/forensicpcap](https://github.com/madpowah/forensicpcap) a Python Network Forensic tool to analyze a PCAP file.
- [**28**Star][6y] [Py] [c0d3sh3lf/android_forensics](https://github.com/c0d3sh3lf/android_forensics) Bypassing Android Pattern Lock
- [**27**Star][3y] [Java] [animeshshaw/chromeforensics](https://github.com/animeshshaw/chromeforensics) A tool to perform automated forensic analysis of Chrome Browser.
- [**26**Star][4y] [Py] [cyberhatcoil/acf](https://github.com/cyberhatcoil/acf) Android Connections Forensics
- [**24**Star][7y] [Ruby] [chrislee35/flowtag](https://github.com/chrislee35/flowtag) FlowTag visualizes pcap files for forensic analysis
- [**24**Star][3y] [Py] [forensicmatt/pancakeviewer](https://github.com/forensicmatt/pancakeviewer) A DFVFS Backed Forensic Viewer
- [**23**Star][3m] [Pascal] [nannib/imm2virtual](https://github.com/nannib/imm2virtual) This is a GUI (for Windows 64 bit) for a procedure to virtualize your EWF(E01), DD (raw), AFF disk image file without converting it, directly with VirtualBox, forensically proof.
- [**22**Star][2y] [C] [lorecioni/imagesplicingdetection](https://github.com/lorecioni/imagesplicingdetection) Illuminant inconsistencies for image splicing detection in forensics
- [**22**Star][1y] [C] [paul-tew/lifer](https://github.com/paul-tew/lifer) Windows link file forensic examiner
- [**22**Star][3m] [Py] [circl/forensic-tools](https://github.com/circl/forensic-tools) CIRCL system forensic tools or a jumble of tools to support forensic
- [**21**Star][2y] [Py] [harris21/afot](https://github.com/harris21/afot) Automation Forensics Tool for Windows
- [**20**Star][5y] [JS] [jonstewart/sifter](https://github.com/jonstewart/sifter) Indexed search and clustering tool for digital forensics
- [**19**Star][3y] [Py] [lukdog/backtolife](https://github.com/lukdog/backtolife) Memory forensic tool for process resurrection starting from a memory dump
- [**18**Star][3y] [C++] [nshadov/screensaver-mouse-jiggler](https://github.com/nshadov/screensaver-mouse-jiggler) Hardware arduino based mouse emulator, preventing screen saver locking (eg. during forensic investigation)
- [**18**Star][20d] [Py] [sekoialab/fastir_artifacts](https://github.com/sekoialab/fastir_artifacts) Live forensic artifacts collector
- [**17**Star][Java] [marten4n6/email4n6](https://github.com/marten4n6/email4n6) A simple cross-platform forensic application for processing email files.
- [**16**Star][9m] [Smarty] [forensenellanebbia/xways-forensics](https://github.com/forensenellanebbia/xways-forensics) Personal settings for X-Ways Forensics
- [**15**Star][2m] [Dockerfile] [bitsofinfo/comms-analyzer-toolbox](https://github.com/bitsofinfo/comms-analyzer-toolbox) Tool for forensic analysis, search and graphing of communications content such as email MBOX files and CSV text message data using Elasticsearch and Kibana
- [**13**Star][10m] [Shell] [matthewclarkmay/ftriage](https://github.com/matthewclarkmay/ftriage) Automating forensic data extraction, reduction, and overall triage of cold disk and memory images.
- [**13**Star][1y] [theresafewconors/file-system-forensics](https://github.com/theresafewconors/file-system-forensics) Repo for Reports on forensic analysis of various File Systems (NoWare to Hide)
- [**11**Star][3y] [Py] [nipunjaswal/wireless-forensics-framework](https://github.com/nipunjaswal/wireless-forensics-framework) Wireless Forensics Framework In Python
- [**11**Star][1y] [C++] [shujianyang/btrforensics](https://github.com/shujianyang/btrforensics) Forensic Analysis Tool for Btrfs File System.
- [**10**Star][2y] [PS] [b2dfir/b2response](https://github.com/b2dfir/b2response) Logged PS Remote Command Wrapper for Blue Team Forensics/IR
- [**10**Star][3y] [Py] [sekoialab/fastir_server](https://github.com/sekoialab/fastir_server) The FastIR Server is a Web server to schedule FastIR Collector forensics collect thanks to the FastIR Agent
- [**9**Star][10m] [Perl] [randomaccess3/4n6_stuff](https://github.com/randomaccess3/4n6_stuff) Git for me to put all my forensics stuff
- [**9**Star][8y] [Perl] [superponible/search-strings-extension](https://github.com/superponible/search-strings-extension) srch_strings is a useful tool in digital forensics. Using the "-t d" option will give a byte location for the string. This repository contains two scripts that automatically map the byte location to the filesystem block containing the string.
- [**9**Star][1y] [Py] [svelizdonoso/logfishh](https://github.com/svelizdonoso/logfishh) Logs Forensic Investigator SSH
- [**9**Star][7y] [JS] [thinkski/vinetto](https://github.com/thinkski/vinetto) Forensic tool for examining Thumbs.db files
- [**8**Star][7y] [Py] [agnivesh/aft](https://github.com/agnivesh/aft) [Deprecated] Android Forensic Toolkit
- [**8**Star][2y] [asiamina/a-course-on-digital-forensics](https://github.com/asiamina/a-course-on-digital-forensics) A course on "Digital Forensics" designed and offered in the Computer Science Department at Texas Tech University
- [**8**Star][2m] [PS] [tvfischer/ps-srum-hunting](https://github.com/tvfischer/ps-srum-hunting) PowerShell Script to facilitate the processing of SRUM data for on-the-fly forensics and if needed threat hunting
- [**7**Star][4m] [PS] [1cysw0rdk0/whodunnit](https://github.com/1cysw0rdk0/whodunnit) A PS forensics tool for Scraping, Filtering and Exporting Windows Event Logs
- [**7**Star][3y] [dfax/dfax](https://github.com/dfax/dfax) (DEPRECATED) Digital Forensic Analysis eXpression
- [**7**Star][1y] [Py] [dlcowen/testkitchen](https://github.com/dlcowen/testkitchen) Scripts from The Forensic Lunch Test Kitchen segments
- [**7**Star][3y] [Py] [maurermj08/vftools](https://github.com/maurermj08/vftools) An open source forensic toolkit built on dfVFS
- [**7**Star][2y] [Rust] [rustensic/prefetchkit](https://github.com/rustensic/prefetchkit) A powerful forensic commandline tool for analyzing Microsoft Prefetch files.
- [**7**Star][2y] [socprime/muddywater-apt](https://github.com/socprime/muddywater-apt) an APT group that has been active throughout 2017
- [**6**Star][4y] [C#] [alphadelta/clearbytes](https://github.com/alphadelta/clearbytes) Data forensic tool
- [**6**Star][6m] [Shell] [hestat/calamity](https://github.com/hestat/calamity) A script to assist in processing forensic RAM captures for malware triage
- [**5**Star][1y] [Shell] [kpcyrd/booty](https://github.com/kpcyrd/booty) Minimal forensic/exfiltration/evil-maid/rescue live boot system
- [**5**Star][8m] [zmbf0r3ns1cs/bf-elk](https://github.com/zmbf0r3ns1cs/bf-elk) Burnham Forensics ELK Deployment Files
- [**5**Star][9m] [Py] [obsidianforensics/scripts](https://github.com/obsidianforensics/scripts) Small scripts and POCs related to digital forensics
- [**4**Star][5m] [Py] [bradley-evans/cfltools](https://github.com/bradley-evans/cfltools) A logfile analysis tool for cyberforensics investigators.
- [**4**Star][3y] [jaredthecoder/codestock2017-stuxnet-forensic-analysis](https://github.com/jaredthecoder/codestock2017-stuxnet-forensic-analysis) Slides and demo script for my talk at Codestock 2017
- [**4**Star][3y] [Py] [rotenkatz/ecos_romfs_unpacker](https://github.com/rotenkatz/ecos_romfs_unpacker) It is a simple ecos ROMFS unpacker for forensics and firmware analysis needs
- [**3**Star][2y] [Py] [bedazzlinghex/memory-analysis](https://github.com/bedazzlinghex/memory-analysis) Contains tools to perform malware and forensic analysis in Memory
- [**3**Star][1y] [Py] [inp2/sherlock](https://github.com/inp2/sherlock) a digital forensic analysis toolkit that relies on graph theory, link analysis, and probabilistic graphical models in order to aid the examiner in digital forensic investigations.
- [**2**Star][2y] [Py] [edisonljh/hadoop_ftk](https://github.com/edisonljh/hadoop_ftk) Hadoop File System Forensics Toolkit
- [**2**Star][C] [enrico204/unhide](https://github.com/enrico204/unhide) A fork of original "unhide" forensics tool from SourceForge CVS
- [**2**Star][4m] [Py] [docker-forensics-toolkit/toolkit](https://github.com/docker-forensics-toolkit/toolkit) A toolkit for the post-mortem examination of Docker containers from forensic HDD copies
- [**2**Star][1m] [Py] [thebeanogamer/hstsparser](https://github.com/thebeanogamer/hstsparser) A tool to parse Firefox and Chrome HSTS databases into forensic artifacts!
- [**1**Star][3m] [Go] [cdstelly/nugget](https://github.com/cdstelly/nugget) A Domain Specific Language for Digital Forensics
- [**1**Star][3y] [C++] [colinmckaycampbell/rapidfilehash](https://github.com/colinmckaycampbell/rapidfilehash) Fast and powerful SHA256 hashing for malware detection and digital forensics.
- [**1**Star][6m] [Py] [pagabuc/atomicity_tops](https://github.com/pagabuc/atomicity_tops) Introducing the Temporal Dimension to Memory Forensics - ACM Transactions on Privacy and Security 2019
- [**1**Star][2y] [Py] [trolldbois/python-haystack-reverse](https://github.com/trolldbois/python-haystack-reverse) Memory forensics data structure reversing
- [**0**Star][4y] [bedazzlinghex/disk-analysis](https://github.com/bedazzlinghex/disk-analysis) Contains tools to perform malware and forensic analysis on disk
- [**0**Star][3y] [C] [irq8/trackercat](https://github.com/irq8/trackercat) A GPS Forensics Utility to Parse GPX Files


***


## <a id="bd653a0f2c8ff4aab78bb2be2257362b"></a>LinuxDistro


- [**127**Star][11m] [Shell] [wmal/kodachi](https://github.com/wmal/kodachi) Linux Kodachi operating system, based on Xubuntu 18.04, provide you with a secure, anti-forensic, and anonymous operating system considering all features that a person who is concerned about privacy would need to have in order to be secure.
- [**104**Star][6y] [santoku/santoku-linux](https://github.com/santoku/santoku-linux) Linux Distro for Mobile Security, Malware Analysis, and Forensics
- [**13**Star][4y] [nelenkov/santoku-linux](https://github.com/nelenkov/santoku-linux) Linux Distro for Mobile Security, Malware Analysis, and Forensics


***


## <a id="601dcc03dc2254612e1b88816ae2b820"></a>Resource Collection


- [**3230**Star][14d] [Rich Text Format] [the-art-of-hacking/h4cker](https://github.com/The-Art-of-Hacking/h4cker) thousands of resources related to ethical hacking / penetration testing, digital forensics and incident response (DFIR), vulnerability research, exploit development, reverse engineering, and more.
- [**841**Star][2m] [cugu/awesome-forensics](https://github.com/cugu/awesome-forensics) A curated list of awesome forensic analysis tools and resources
- [**265**Star][10d] [Py] [den4uk/andriller](https://github.com/den4uk/andriller) a collection of forensic tools for smartphones
- [**76**Star][3m] [ivbeg/awesome-forensicstools](https://github.com/ivbeg/awesome-forensicstools) Awesome list of digital forensic tools
- [**12**Star][27d] [gaurav-gogia/dftools](https://github.com/gaurav-gogia/dftools) A curated list of digital forensic tools.
- [**10**Star][4y] [Py] [randomsctf/ctf-scripts](https://github.com/randomsctf/ctf-scripts) A collection of short scripts for analysis, encryption and forensics, that can be used for CTF and/or security assessments
- [**8**Star][26d] [Shell] [kbnlresearch/forensicimagingresources](https://github.com/kbnlresearch/forensicimagingresources) resources and documentation related to an effort at setting up an experimental small-scale forensic imaging facility.
- [**4**Star][2y] [netseclab/paper_for_digital_forensics](https://github.com/netseclab/paper_for_digital_forensics) This is a collection of papers, codes, issues for digital forensics.
- [**2**Star][2y] [kanglib/edu_for](https://github.com/kanglib/edu_for) A cheat sheet for digital forensics


***


## <a id="4d2a33083a894d6e6ef01b360929f30a"></a>Volatility


- [**3276**Star][3m] [Py] [volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility) An advanced memory forensics framework
- [**326**Star][9m] [Py] [jasonstrimpel/volatility-trading](https://github.com/jasonstrimpel/volatility-trading) A complete set of volatility estimators based on Euan Sinclair's Volatility Trading
- [**293**Star][3y] [Py] [kevthehermit/volutility](https://github.com/kevthehermit/volutility) Web App for Volatility framework
- [**226**Star][3m] [Py] [volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) Volatility profiles for Linux and Mac OS X
- [**222**Star][2y] [JS] [jameshabben/evolve](https://github.com/jameshabben/evolve) Web interface for the Volatility Memory Forensics Framework
- [**220**Star][1m] [Py] [volatilityfoundation/community](https://github.com/volatilityfoundation/community) Volatility plugins developed and maintained by the community
- [**217**Star][3y] [Py] [mkorman90/volatilitybot](https://github.com/mkorman90/volatilitybot) An automated memory analyzer for malware samples and memory dumps
- [**197**Star][11d] [Py] [jpcertcc/malconfscan](https://github.com/jpcertcc/malconfscan) Volatility plugin for extracts configuration data of known malware
- [**171**Star][2m] [Py] [gleeda/memtriage](https://github.com/gleeda/memtriage) Allows you to quickly query a Windows machine for RAM artifacts
- [**162**Star][2y] [Py] [aim4r/voldiff](https://github.com/aim4r/voldiff) Malware Memory Footprint Analysis based on Volatility
- [**149**Star][21d] [Py] [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) Volatility 3.0 development
- [**131**Star][8m] [Py] [kd8bny/limeaide](https://github.com/kd8bny/limeaide) A python application designed to remotely dump RAM of a Linux client and create a volatility profile for later analysis on your local host.
- [**130**Star][4y] [Py] [elceef/bitlocker](https://github.com/elceef/bitlocker) Volatility Framework plugin for extracting BitLocker FVEK (Full Volume Encryption Key)
- [**90**Star][5m] [Py] [tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) Autoruns plugin for the Volatility framework
- [**76**Star][2y] [Py] [superponible/volatility-plugins](https://github.com/superponible/volatility-plugins) Plugins I've written for Volatility
- [**71**Star][3y] [Py] [monnappa22/hollowfind](https://github.com/monnappa22/hollowfind) a Volatility plugin to detect different types of process hollowing techniques used in the wild to bypass, confuse, deflect and divert the forensic analysis techniques
- [**61**Star][3y] [Py] [fireeye/volatility-plugins](https://github.com/fireeye/volatility-plugins)  plugins for the Volatility Framework.
- [**44**Star][3y] [Py] [tribalchicken/volatility-filevault2](https://github.com/tribalchicken/volatility-filevault2) Volatility plugin to extract FileVault 2 VMK's
- [**43**Star][6y] [Py] [sketchymoose/totalrecall](https://github.com/sketchymoose/totalrecall) Based on the Volatility framework, this script will run various plugins as well as create a timeline, or use YARA/ClamAV/VirusTotal to find badness.
- [**43**Star][3y] [Py] [tylerha97/findevil](https://github.com/tylerha97/findevil) Volatility plugin to find evil
- [**40**Star][3m] [Py] [fireeye/win10_volatility](https://github.com/fireeye/win10_volatility) An advanced memory forensics framework
- [**39**Star][4y] [Py] [takahiroharuyama/openioc_scan](https://github.com/takahiroharuyama/openioc_scan) openioc_scan Volatility Framework plugin
- [**38**Star][3y] [Py] [cysinfo/pymal](https://github.com/cysinfo/pymal) PyMal is a python based interactive Malware Analysis Framework. It is built on the top of three pure python programes Pefile, Pydbg and Volatility.
- [**38**Star][3y] [Py] [kevthehermit/volatility_plugins](https://github.com/kevthehermit/volatility_plugins) Volatility Plugins
- [**33**Star][1y] [Py] [eset/volatility-browserhooks](https://github.com/eset/volatility-browserhooks) Volatility Framework plugin to detect various types of hooks as performed by banking Trojans
- [**32**Star][4y] [Py] [csababarta/volatility_plugins](https://github.com/csababarta/volatility_plugins) Volatility plugins created by the author
- [**32**Star][2y] [Py] [eurecom-s3/linux_screenshot_xwindows](https://github.com/eurecom-s3/linux_screenshot_xwindows) Volatility plugin to extract X screenshots from a memory dump
- [**29**Star][2y] [Py] [tribalchicken/volatility-bitlocker](https://github.com/tribalchicken/volatility-bitlocker) Volatility plugin to extract BitLocker Full Volume Encryption Keys (FVEK)
- [**28**Star][5y] [Py] [phaeilo/vol-openvpn](https://github.com/phaeilo/vol-openvpn) A Volatility plugin to extract credentials from the memory of a OpenVPN client.
- [**25**Star][2m] [Py] [cube0x8/chrome_ragamuffin](https://github.com/cube0x8/chrome_ragamuffin) Google Chrome internals analysis using Volatility
- [**22**Star][4y] [Py] [monnappa22/linux_mem_diff_tool](https://github.com/monnappa22/linux_mem_diff_tool) Script to perform Linux Memory Diff Analysis Using Volatility
- [**22**Star][1y] [Py] [sebastienbr/volatility](https://github.com/sebastienbr/volatility) Utilities for the memory forensics framework
- [**22**Star][5y] [Py] [siliconblade/volatility](https://github.com/siliconblade/volatility) volatility
- [**21**Star][6y] [Py] [carlpulley/volatility](https://github.com/carlpulley/volatility) A collection of Volatility Framework plugins.
- [**21**Star][2y] [Py] [kslgroup/threadmap](https://github.com/kslgroup/threadmap) threadmap plugin for Volatility Foundation
- [**20**Star][5y] [kdpryor/linuxvolprofiles](https://github.com/kdpryor/linuxvolprofiles) Volatility Linux Profiles
- [**19**Star][3y] [Py] [monnappa22/psinfo](https://github.com/monnappa22/psinfo) Psinfo is a Volatility plugin which collects the process related information from the VAD (Virtual Address Descriptor) and PEB (Process Enivornment Block) and displays the collected information and suspicious memory regions for all the processes running on the system. This plugin should allow a security analyst to get the process related informa…
- [**18**Star][3y] [Py] [bridgeythegeek/editbox](https://github.com/bridgeythegeek/editbox) EditBox is a plugin for the Volatility Framework. It extracts the text from Windows Edit controls, that is, textboxes as generated by Windows Common Controls.
- [**18**Star][2y] [iabadia/volatility-plugin-tutorial](https://github.com/iabadia/volatility-plugin-tutorial) Development guide for Volatility Plugins
- [**17**Star][6y] [Py] [dutchy-/volatility-plugins](https://github.com/dutchy-/volatility-plugins) Container for assorted volatility plugins.
- [**16**Star][1y] [Py] [andreafortuna/malhunt](https://github.com/andreafortuna/malhunt) Hunt malware with Volatility
- [**16**Star][4m] [Dockerfile] [blacktop/docker-volatility](https://github.com/blacktop/docker-volatility) Volatility Dockerfile
- [**16**Star][2y] [Py] [borjamerino/doublepulsar-volatility](https://github.com/borjamerino/doublepulsar-volatility) Volatility plugin to help identify DoublePulsar implant by listing the array of pointers SrvTransaction2DispatchTable from the srv.sys driver.
- [**16**Star][6m] [Py] [mbrown1413/sqlitefind](https://github.com/mbrown1413/sqlitefind) A Volatility plugin for finding sqlite database rows
- [**13**Star][12m] [Py] [citronneur/volatility-wnf](https://github.com/citronneur/volatility-wnf) Browse and dump Windows Notification Facilities
- [**12**Star][6y] [Py] [jeffbryner/volatilityplugins](https://github.com/jeffbryner/volatilityplugins) My volatility Plugins
- [**11**Star][4y] [Py] [4armed/volatility-attributeht](https://github.com/4armed/volatility-attributeht) 
- [**11**Star][5y] [Py] [tomspencer/volatility](https://github.com/tomspencer/volatility) Volatility stuff
- [**11**Star][5y] [Py] [kudelskisecurity/volatility-plugins](https://github.com/kudelskisecurity/Volatility-plugins) Volatility plugins
- [**10**Star][2y] [Py] [circl/volatility-misp](https://github.com/circl/volatility-misp) Volatility plugin to interface with MISP
- [**9**Star][1m] [Py] [dhondta/appmemdumper](https://github.com/dhondta/appmemdumper) Forensics triage tool relying on Volatility and Foremost
- [**9**Star][11m] [Py] [pengjin2/derbit-volatility-visulization](https://github.com/pengjin2/derbit-volatility-visulization) Visualization Tool for Deribit Options
- [**9**Star][5m] [MATLAB] [tommasobelluzzo/historicalvolatility](https://github.com/tommasobelluzzo/historicalvolatility) A framework for historical volatility estimation and analysis.
- [**8**Star][3y] [Py] [martink90/volatilitybot_public](https://bitbucket.org/martink90/volatilitybot_public) 
- [**8**Star][6y] [C#] [andy5876/volatility-plugin-manager](https://github.com/andy5876/volatility-plugin-manager) GUI interface for Volatility
- [**8**Star][1y] [Py] [countercept/volatility-plugins](https://github.com/countercept/volatility-plugins) 
- [**8**Star][2y] [C] [lixingchen12138/libvmi-volatility-master](https://github.com/lixingchen12138/libvmi-volatility-master) 虚拟机带外内存监控
- [**8**Star][3m] [Py] [swelcher/vol2log](https://github.com/swelcher/vol2log) 解析Volatility Json格式输出并导入至Graylog
- [**7**Star][4y] [Py] [bridgeythegeek/ndispktscan](https://github.com/bridgeythegeek/ndispktscan) NDISPktScan is a plugin for the Volatility Framework. It parses the Ethernet packets stored by ndis.sys in Windows kernel space memory.
- [**7**Star][4m] [Java] [esterhlav/black-scholes-option-pricing-model](https://github.com/esterhlav/black-scholes-option-pricing-model) Black Scholes Option Pricing calculator with Greeks and implied volatility computations. Geometric Brownian Motion simulator with payoff value diagram and volatility smile plots. Java GUI.
- [**7**Star][1y] [mattnotmax/volatility_mind_map](https://github.com/mattnotmax/volatility_mind_map) A Volatility command reference mind map
- [**5**Star][2y] [R] [niki864/volatilityanalysisbitcoin](https://github.com/niki864/volatilityanalysisbitcoin) A technical analysis of price volatility in bitcoins for a over a year using 6 hour intervals
- [**4**Star][6m] [Py] [carlospolop/autovolatility](https://github.com/carlospolop/autovolatility) Run several volatility plugins at the same time
- [**4**Star][3y] [HTML] [luisdamiano/rfinance17](https://github.com/luisdamiano/rfinance17) Presentation and notebook for the lightning talk A Quick Intro to Hidden Markov Models Applied to Stock Volatility presented in R/Finance 2017.
- [**3**Star][2y] [R] [prodipta/bsoption](https://github.com/prodipta/bsoption) Package for option pricing and volatility calibration for index (and FX) options
- [**2**Star][7m] [PHP] [yegor256/volatility](https://github.com/yegor256/volatility) The Calculator of the Source Code "Volatility" Metric
- [**1**Star][2y] [Py] [samduy/volatility-uclinux](https://github.com/samduy/volatility-uclinux) Volatility profile for uclinux
- [**1**Star][2m] [Py] [mdenzel/acpi-rootkit-scan](https://github.com/mdenzel/acpi-rootkit-scan) volatility plugin to detect ACPI rootkits
- [**1**Star][11m] [Py] [tazwake/volatility-plugins](https://github.com/tazwake/volatility-plugins) Learning volatility plugins.
- [**1**Star][7m] [Py] [angelomirabella/linux_coredump](https://github.com/angelomirabella/linux_coredump) Volatility plugin that attempts to create a core dump file starting from the memory of a Linux process
- [**1**Star][4m] [Py] [kslgroup/winobj](https://github.com/kslgroup/winobj) A volatility plugin to parse Object Directories
- [**0**Star][5y] [mohandattatreya/4n6k_volatility_installer](https://github.com/mohandattatreya/4n6k_volatility_installer) Installs Volatility 2.4 (+ all dependencies) for Ubuntu (+ other APT-based distros) with one command.
- [**0**Star][19d] [Py] [orchechik/ropfind](https://github.com/orchechik/ropfind) Volatility Plugins to find rop gadgets in Windows and Linux physical memory dumps.
- [**0**Star][4m] [Py] [kslgroup/tokenimp-token_impersonation_detection](https://github.com/kslgroup/tokenimp-token_impersonation_detection) A volatility plugin to detect Token Impersonation


***


## <a id="8159418f807637a0d70406803a3c08c5"></a>sleuthkit


- [**1482**Star][11d] [C] [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit)  a library and collection of command line digital forensics tools that allow you to investigate volume and file system data.
- [**840**Star][9d] [Java] [sleuthkit/autopsy](https://github.com/sleuthkit/autopsy)  a digital forensics platform and graphical interface to The Sleuth Kit® and other digital forensics tools. 
- [**26**Star][2m] [blackbagtech/sleuthkit-apfs](https://github.com/blackbagtech/sleuthkit-apfs) A fork of The Sleuthkit with Pooled Storage and APFS support. See
- [**6**Star][3y] [Pascal] [nannib/nbtempow](https://github.com/nannib/nbtempow)  a forensic tool for making timelines from block devices image files (raw, ewf,physicaldrive, etc.
- [**1**Star][3m] [Shell] [nannib/nbtempo](https://github.com/nannib/nbtempo)  a GUI (Graphical User Interface) Bash script for making files timelines and reporting them in CSV (electronic sheet) format. 


***


## <a id="0b1db12ec509cd6fb489c93a4cc837d5"></a>Rekall


- [**1522**Star][10m] [Py] [google/rekall](https://github.com/google/rekall) Rekall Memory Forensic Framework
- [**82**Star][1y] [HTML] [google/rekall-profiles](https://github.com/google/rekall-profiles) Public Profile Repository for Rekall Memory Forensic.
- [**5**Star][4y] [bmaia/rekall-profiles](https://github.com/bmaia/rekall-profiles) Rekall Memory Forensic Linux Profiles
- [**2**Star][25d] [Py] [f-block/rekall-plugins](https://github.com/f-block/rekall-plugins) 


***


## <a id="0d23b542d7b0b1069a91f6c500009c3a"></a>bulk_extractor


- [**391**Star][19d] [C++] [simsong/bulk_extractor](https://github.com/simsong/bulk_extractor) bulk_extractor
- [**11**Star][3y] [Java] [nps-deep/sectorscope](https://github.com/NPS-DEEP/SectorScope) A GUI for viewing block hashes found using hashdb and bulk_extractor
- [**0**Star][2y] [Lex] [thomaslaurenson/irdnumberscanner](https://github.com/thomaslaurenson/irdnumberscanner) A bulk_extractor scanner plug-in to detect and validate Inland Revenue (IRD) Numbers


***


## <a id="bd015dd7245b420dca75a267133ddce3"></a>Anti-Forensic


- [**2736**Star][3y] [Py] [hephaest0s/usbkill](https://github.com/hephaest0s/usbkill) an anti-forensic kill-switch that waits for a change on your USB ports and then immediately shuts down your computer.
- [**339**Star][2y] [C] [natebrune/silk-guardian](https://github.com/natebrune/silk-guardian) an anti-forensic kill-switch that waits for a change on your usb ports and then wipes your ram, deletes precious files, and turns off your computer.
- [**78**Star][2y] [C] [elfmaster/saruman](https://github.com/elfmaster/saruman) ELF anti-forensics exec, for injecting full dynamic executables into process image (With thread injection)
- [**67**Star][3y] [Shell] [trpt/usbdeath](https://github.com/trpt/usbdeath) anti-forensic tool that writes udev rules for known usb devices and do some things at unknown usb insertion or specific usb device removal
- [**35**Star][1y] [C] [ntraiseharderror/kaiser](https://github.com/ntraiseharderror/kaiser) Fileless persistence, attacks and anti-forensic capabilties.
- [**20**Star][3y] [Py] [ncatlin/lockwatcher](https://github.com/ncatlin/lockwatcher) Anti-forensic monitor program: watches for signs of tampering and purges keys/shuts everything down.
- [**15**Star][1y] [C#] [thereisnotime/xxusbsentinel](https://github.com/thereisnotime/xxusbsentinel) Windows anti-forensics USB monitoring tool.
- [**12**Star][5y] [C#] [maldevel/clearlogs](https://github.com/maldevel/clearlogs) Clear All Windows System Logs - AntiForensics
- [**11**Star][3y] [Shell] [phosphore/burn](https://github.com/phosphore/burn) [WIP] Anti-Forensics ToolKit to clear post-intrusion sensible logfiles


***


## <a id="9c0413531a5b5afd12b89ccdc744afbd"></a>macOS


- [**3071**Star][10m] [JS] [jipegit/osxauditor](https://github.com/jipegit/osxauditor) OS X Auditor is a free Mac OS X computer forensics tool
- [**1695**Star][6m] [Py] [yelp/osxcollector](https://github.com/yelp/osxcollector) A forensic evidence collection & analysis toolkit for OS X
- [**445**Star][2y] [ObjC] [aburgh/disk-arbitrator](https://github.com/aburgh/disk-arbitrator) A Mac OS X forensic utility which manages file system mounting in support of forensic procedures.
- [**317**Star][9m] [Py] [n0fate/chainbreaker](https://github.com/n0fate/chainbreaker) Mac OS X Keychain Forensic Tool
- [**197**Star][1y] [Py] [pstirparo/mac4n6](https://github.com/pstirparo/mac4n6) Collection of forensics artifacs location for Mac OS X and iOS
- [**38**Star][10d] [Py] [ydkhatri/macforensics](https://github.com/ydkhatri/macforensics) Scripts to process OSX forensic artifacts
- [**16**Star][1y] [mrmugiwara/ftk-imager-osx](https://github.com/mrmugiwara/ftk-imager-osx) FTK Imager a Forensics Tools For MAC OS X


***


## <a id="a93df189246db405e8182a42d3f7e553"></a>iOS


- [**33**Star][2m] [Py] [cheeky4n6monkey/ios_sysdiagnose_forensic_scripts](https://github.com/cheeky4n6monkey/ios_sysdiagnose_forensic_scripts) Scripts to parse various iOS sysdiagnose logs. Based upon the forensic research of Mattia Epifani, Heather Mahalik and Cheeky4n6monkey.
- [**28**Star][6y] [Py] [flo354/iosforensic](https://github.com/flo354/iosforensic) iOS forensic tool


***


## <a id="505d67a56d03c921dd19737c28c3d8fc"></a>Linux


- [**320**Star][5m] [HTML] [intezer/linux-explorer](https://github.com/intezer/linux-explorer) Easy-to-use live forensics toolbox for Linux endpoints
- [**295**Star][1y] [Shell] [sevagas/swap_digger](https://github.com/sevagas/swap_digger) a tool used to automate Linux swap analysis during post-exploitation or forensics.
- [**102**Star][2m] [ashemery/linuxforensics](https://github.com/ashemery/LinuxForensics) Everything related to Linux Forensics
- [**36**Star][4y] [Shell] [pwnagentsmith/ir_tool](https://github.com/pwnagentsmith/ir_tool) Script for Forensic on Linux
- [**34**Star][2y] [Py] [google/amt-forensics](https://github.com/google/amt-forensics) Retrieve Intel AMT's Audit Log from a Linux machine without knowing the admin user's password.
- [**26**Star][2y] [packtpublishing/digital-forensics-with-kali-linux](https://github.com/packtpublishing/digital-forensics-with-kali-linux) Digital Forensics with Kali Linux, published by Packt
- [**10**Star][3y] [C] [t0t3m/afkit](https://github.com/t0t3m/afkit) Anti live forensic linux LKM rootkit
- [**3**Star][2y] [Pascal] [esperti/nbtempox](https://github.com/esperti/nbtempox) a GNU-Linux forensic tool for making timelines (in CSV format) from block devices image files (raw, ewf,physicaldrive, etc.)


# Contribute
Contents auto exported by Our System, please raise Issue if you have any question.