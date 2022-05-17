# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['../main.py'],
             pathex=['.', 'app', 'scripts', ],
             binaries=[('../app/key.key', 'app'),],
             datas=[('../app', 'app',), ('../scripts', 'scripts',), ('../security-data-oval-com.redhat.rhsa-RHEL8.xml', 'security-data-oval-com.redhat.rhsa-RHEL8.xml',), ('../security-data-oval-com.redhat.rhsa-RHEL7.xml', 'security-data-oval-com.redhat.rhsa-RHEL7.xml'),],
             hiddenimports=['netifaces', 'psutil', 'distro', 'lxml', 'logging', 'nmap3', 'pyndiff', 'time', 'random', 'difflib', 'xmltodict', 'pandas', 'shutil', 'rich', 'rich.logging', 'rich.logging.RichHandler', 'deepdiff', 'json2xml', 'xmldiff', 'xmldiff.main', 'json2xml.utils', 'json2xml.json2xml', 'six', ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [('v', None, 'OPTION')],
          name='rhelhostinfo.bin',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir='/opt/rhelhostinfo/runtime',
          console=True,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None)
