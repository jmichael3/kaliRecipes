if [ $# -ne 1 ]
then
	printf "%s\n" "[-]Usage: ${0} [IMAGE_NAME]"
	exit 1
else
	IMG_NAME=$(printf "%s" "${1}"|sed 's| |_|g')
fi

# set up build environment
if [ "$(lsb_release -si 2>/dev/null)" = 'Kali' ]
then
	printf "%s\n" '[*]Kali detected...'
	sudo apt update -y
	sudo apt install -y git live-build simple-cdd cdebootstrap curl wget tor torsocks
	sudo apt install -y --fix-broken

# https://unix.stackexchange.com/questions/29981/how-can-i-tell-whether-a-build-is-debian-based
elif [ -f /etc/debian_version ] || (grep -Eiq 'debian|buntu|mint' /etc/*release)
then
	printf "%s\n" '[*]Debian-based OS detected...'
	sudo apt update -y
	sudo apt full-upgrade -y
	wget -q https://http.kali.org/pool/main/k/kali-archive-keyring/kali-archive-keyring_2022.1_all.deb
	wget -q https://http.kali.org/kali/pool/main/l/live-build/live-build_20230131_all.deb
	sudo apt install -y git live-build simple-cdd cdebootstrap curl wget tor torsocks
	sudo apt install -y --fix-broken
	sudo dpkg -i kali-archive-keyring_2022.1_all.deb
	sudo dpkg -i live-build_20230131_all.deb
	rm -f live-build_20230131_all.deb kali-archive-keyring_2022.1_all.deb
	cd /usr/share/debootstrap/scripts/ || exit 1
	(echo "default_mirror http://http.kali.org/kali"; \
		sed -e "s/debian-archive-keyring.gpg/kali-archive-keyring.gpg/g" sid) > /tmp/kali
	sudo mv /tmp/kali .
	sudo ln -s kali kali-rolling
	cd - || exit 1
else
	printf "%s\n" '[-]build script must be ran on kali or debian-based os'
	exit 1
fi


# set up working dir(s)
for DIRECTORY in images "local-config/${IMG_NAME}/skel" "local-config/${IMG_NAME}/backgrounds" "local-config/${IMG_NAME}/bin"
do
	if [ ! -d "kali-build/${DIRECTORY}" ]
	then
		sudo mkdir -p "kali-build/${DIRECTORY}"
	fi
done
CURRENT_USER="$(whoami)"
sudo chown -R "${CURRENT_USER}:${CURRENT_USER}" kali-build


# ensure clean build-config
# https://gitlab.com/kalilinux/recipes/live-build-config-examples/-/blob/master/offsec-awae-live.sh
printf "%s\n" '[*]Getting base-image build-script...'
if [ -d kali-build/live-build-config ]
then
	cd kali-build/live-build-config || exit 1
	git reset --hard HEAD >/dev/null
	git clean -f -d >/dev/null
	git pull >/dev/null
else
	git clone https://gitlab.com/kalilinux/build-scripts/live-build-config.git kali-build/live-build-config
	cd kali-build/live-build-config || exit 1
fi


# POSIX compliant method for retrieving passwords in a secure manner
# https://unix.stackexchange.com/questions/222974/ask-for-a-password-in-posix-compliant-shell
read_password() {
  REPLY="$(
    # always read from the tty even when redirected:
    exec < /dev/tty || exit # || exit only needed for bash

    # save current tty settings:
    tty_settings=$(stty -g) || exit

    # schedule restore of the settings on exit of that subshell
    # or on receiving SIGINT or SIGTERM:
    trap 'stty "$tty_settings"' EXIT INT TERM

    # disable terminal local echo
    stty -echo || exit

    # prompt on tty
    printf "%s" "${1}" > /dev/tty

    # read password as one line, record exit status
    IFS= read -r password; ret=$?

    # display a newline to visually acknowledge the entered password
    echo > /dev/tty

    # return the password for $REPLY
    printf '%s\n' "$password"
    exit "$ret"
  )"
}


# prompt user for needed data
for VARIABLE in live_USERNAME live_FULLNAME live_HOSTNAME
do
	printf "%s: " "${VARIABLE}"
	read -r "${VARIABLE?}"
done
live_USERNAME=$(printf "%s" "${live_USERNAME}"|sed 's| |_|g')
live_HOSTNAME=$(printf "%s" "${live_HOSTNAME}"|sed 's| |_|g')
live_FULLNAME=$(printf "%s" "${live_FULLNAME}")

read_password "live_PASSWORD: "
live_PASSWORD="${REPLY}"
read_password "Retype password: "
if [ "${live_PASSWORD}" = "${REPLY}" ]
then
	live_PASSWORD=$(printf "%s" "${REPLY}"| openssl passwd -6 -stdin)
else
	printf "%s\n" "Passwords didn't match"
	exit 1
fi


printf "%s\n" '[*]Making config changes...'


# create needed directories
for DIRECTORY in root share etc/skel etc/skel/working etc/systemd/system usr/local/bin usr/share/backgrounds/kali
do
	mkdir -p "kali-config/common/includes.chroot/${DIRECTORY}"
done
mkdir -p kali-config/common/packages.chroot/


# change general settings
cat  > kali-config/common/includes.chroot/etc/live/config.conf.d/kali.conf << EOF
# Default kali configuration
LIVE_HOSTNAME="${live_HOSTNAME}"
LIVE_USERNAME="${live_USERNAME}"
LIVE_USER_FULLNAME="${live_FULLNAME}"
EOF
sed -i "s| kali$| ${live_USERNAME}|g" \
	kali-config/common/includes.chroot/usr/lib/live/config/0031-kali-user-setup
sed -i "s|AqLUsDitNnTsw|${live_PASSWORD}|g" \
	kali-config/common/includes.chroot/usr/lib/live/config/0031-kali-user-setup


# specific packages
cat > "kali-config/variant-xfce/package-lists/kali.list.chroot" << EOF
# You always want these:
kali-linux-core
kali-desktop-live

# Metapackages
# For the complete list see: https://tools.kali.org/kali-metapackages
kali-tools-top10

# Graphical desktop
kali-desktop-xfce

# dev
git
gcc
mingw-w64
build-essential
make
cmake
nasm
wget
curl
jq
bat
vim
code-oss
wine
wine32:i386
wine64
python2
python3-venv
python3-autopep8
pylint
python3-dev
python3-pip
python3-setuptools
python3-pwntools
python3-scapy
python3-impacket
python3-pcapy
python3-ropgadget
libglib2.0-dev
libc6-dbg
clang-format
valgrind
shellcheck
strace
ltrace
gdb
ghidra
upx-ucl
xxd
checksec
binwalk

# utils
libreoffice-core
vlc
gimp
thunderbird

# tunneling
sshuttle
openvpn
chisel
proxychains4
tor
torsocks
torbrowser-launcher

# post
peass
linux-exploit-suggester
python3-donut

# essentials
exploitdb
macchanger
hollywood
terminator
tmux
screen
htop
bpytop
neofetch
locate
xclip
net-tools
steghide
gobuster
gospider
dirsearch
python3-shodan
john
hashcat
hashcat-utils
seclists
poppler-utils
EOF


# custom configs
if [ ! -f "../local-config/${IMG_NAME}/skel/.bash_aliases" ]
then
	cat > "../local-config/${IMG_NAME}/skel/.bash_aliases" << EOF
alias lt="ls -altr"
alias shared="cd /share && ls -altr"
alias working="cd /home/\\\${USER}/working && ls -altr"
alias b="cd - && ls -altr"
alias xclip="xclip -selection clipboard"
alias pgrep="pgrep -a"
alias wip="curl -s ipinfo.io| jq"
alias nmap="nmap --privileged"
alias ch="curl -skD - -o /dev/null"
alias gcc="gcc -std=c99 -pedantic-errors -Wall -Wextra"
EOF
fi

if [ ! -f "../local-config/${IMG_NAME}/skel/.gdbinit-gef.py" ]
then
	wget -O "../local-config/${IMG_NAME}/skel/.gdbinit-gef.py" -q https://gef.blah.cat/py
	printf "%s" 'source ~/.gdbinit-gef.py' > "../local-config/${IMG_NAME}/skel/.gdbinit"
fi

if [ ! -f "../local-config/${IMG_NAME}/skel/.clang-format" ]
then
	curl -s 'https://raw.githubusercontent.com/petertorelli/clang-format-barr-c/master/.clang-format'\
	       	-o "../local-config/${IMG_NAME}/skel/.clang-format"
fi

# https://mislav.net/2011/12/vim-revisited/
if [ ! -f "../local-config/${IMG_NAME}/skel/.vimrc" ]
then
	cat > "../local-config/${IMG_NAME}/skel/.vimrc" << EOF
set nocompatible                " choose no compatibility with legacy vi
syntax enable
set encoding=utf-8
set showcmd                     " display incomplete commands
filetype plugin indent on       " load file type plugins + indentation

"" Whitespace
set nowrap                      " don't wrap lines
set tabstop=4 shiftwidth=4      " a tab is two spaces (or set this to 4)
set expandtab                   " use spaces, not tabs (optional)
set backspace=indent,eol,start  " backspace through everything in insert mode

"" Searching
set hlsearch                    " highlight matches
set incsearch                   " incremental searching
set ignorecase                  " searches are case insensitive...
set smartcase                   " ... unless they contain at least one capital letter
EOF
fi
find "../local-config/${IMG_NAME}/skel/" -type f -exec cp {} kali-config/common/includes.chroot/root \;
find "../local-config/${IMG_NAME}/skel/" -type f -exec cp {} kali-config/common/includes.chroot/etc/skel \;


# custom tools
if [ ! -f "../local-config/${IMG_NAME}/bin/anew" ]
then
	curl -s -LO 'https://github.com/tomnomnom/anew/releases/download/v0.1.1/anew-linux-386-0.1.1.tgz'
	tar -xvzf 'anew-linux-386-0.1.1.tgz' -C "../local-config/${IMG_NAME}/bin/"
	rm -f 'anew-linux-386-0.1.1.tgz'
fi

if [ ! -f "../local-config/${IMG_NAME}/bin/xresize" ]
then
	cat > "../local-config/${IMG_NAME}/bin/xresize" << EOF
PATH=/usr/bin
DISPLAY=:0
export DISPLAY
desktopuser="\$(/bin/ps -ef  | /bin/grep -oP '^\\w+ (?=.*vdagent( |$))')" || exit 0
XAUTHORITY=\$(eval echo "~\$desktopuser")/.Xauthority
export XAUTHORITY
xrandr --output "\$(xrandr | awk '/ connected/{print \$1; exit; }')" --auto
EOF
fi

if [ ! -f "../local-config/${IMG_NAME}/bin/ms" ]
then
	cat > "../local-config/${IMG_NAME}/bin/ms" << EOF
mount -t 9p -o trans=virtio /share /share/
EOF
fi

find "../local-config/${IMG_NAME}/bin/" -type f -exec cp {} kali-config/common/includes.chroot/usr/local/bin/ \;


# custom wallpapers
if [ ! -f "../local-config/${IMG_NAME}/backgrounds/default-background.jpg" ]
then
	wget -O "../local-config/${IMG_NAME}/backgrounds/default-background.jpg" -q \
		'https://www.pixelstalk.net/wp-content/uploads/2016/05/Futuristic-HD-Wallpapers.jpg'
fi
if [ ! -f "../local-config/${IMG_NAME}/backgrounds/default-lockscreen.jpg" ]
then
	wget -O "../local-config/${IMG_NAME}/backgrounds/default-lockscreen.jpg" -q \
		'https://www.pixelstalk.net/wp-content/uploads/2016/05/3D-Futuristic-Room-Wallpaper.jpg'
fi
find "../local-config/${IMG_NAME}/backgrounds/" -type f -exec cp {} \
	kali-config/common/includes.chroot/usr/share/backgrounds/kali/ \;


# startup actions
# https://forums.kali.org/showthread.php?36072-SOLVED-Could-not-change-MAC-amp-Setup-Macchanger-auto-spoofing-randomization-in-Kali
cat > kali-config/common/includes.chroot/etc/systemd/system/macspoof@.service << EOF
[Unit]
Description=macchanger on %I
Wants=network-pre.target
Before=network-pre.target
After=sys-subsystem-net-devices-%i.device

[Service]
ExecStart=/usr/bin/macchanger -r %I
Type=oneshot

[Install]
WantedBy=multi-user.target 
EOF

cat > kali-config/common/hooks/live/01-my-custom-hooks.chroot << EOF
# change binaries to executable
find /usr/local/bin/ -type f -exec chmod +x {} \;

# change default backgrounds
unlink /usr/share/backgrounds/kali-16x9/default
ln -s /usr/share/backgrounds/kali/default-background.jpg /usr/share/backgrounds/kali-16x9/default

unlink /usr/share/desktop-base/kali-theme/login/background
ln -s /usr/share/backgrounds/kali/default-lockscreen.jpg /usr/share/desktop-base/kali-theme/login/background

# startup services
systemctl enable macspoof@wlan0.service 
systemctl enable macspoof@wlan1.service 
systemctl enable macspoof@wlan2.service 
EOF
chmod +x kali-config/common/hooks/live/01-my-custom-hooks.chroot


# change boot options
sed -i "s|--bootappend-live \"boot=live components quiet splash noeject\"\
|--bootappend-live \"boot=live components quiet splash noeject toram systemd.swap=no noautomount nozsh\"\
|g" auto/config

sed -i "s|--bootappend-install \"net.ifnames=0\"\
|--bootappend-install \"net.ifnames=0 nozsh\"\
|g" auto/config

sed -i 's|insmod play|#insmod play|g' kali-config/common/bootloaders/grub-pc/config.cfg
sed -i 's|play 960 440 1 0 4 440 1|#play 960 440 1 0 4 440 1|g' kali-config/common/bootloaders/grub-pc/config.cfg
sed -i '/set default=0/a set timeout=0' live-build-config/kali-config/common/bootloaders/grub-pc/config.cfg


# build
printf "%s\n" '[*]Building...'
sudo ./build.sh \
	--verbose \
	--debug \
	--live \
	--variant xfce \
	--version 2022.4 \
	--subdir kali-2022.4


# post process
cd ../ || exit 1
isoPath=$(find live-build-config/images/ -name '*.iso'|head -n1)
newIsoPath="images/${IMG_NAME}.iso"
if [ -f "${isoPath}" ]
then
	printf "%s\n" "[*]Moving iso to ${PWD}/${newIsoPath}"
	sudo mv "${isoPath}" "${newIsoPath}"
	sudo chown -R "${CURRENT_USER}:${CURRENT_USER}" images/
else
	printf "%s\n" '[-]Build failed'
	exit 1
fi

if [ -f "${newIsoPath}" ]
then
	isoPath="${newIsoPath}"
else
	printf "%s\n" '[-]Failed to move iso...'
fi

{ printf "%s\n" "${IMG_NAME}"; \
	printf "%s\n" '----------------------'; \
	date; date -u; date +%s; \
	printf "\n"; \
	kaliHash=$(md5sum "${isoPath}"); printf "%s\n" "hash: ${kaliHash}"; \
	printf "%s\n" '======================'; } | tee -a info.txt

printf "%s\n" '[+]Done!!!'

