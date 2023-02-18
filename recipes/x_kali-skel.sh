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
	wget https://http.kali.org/pool/main/k/kali-archive-keyring/kali-archive-keyring_2022.1_all.deb
	wget https://http.kali.org/kali/pool/main/l/live-build/live-build_20230131_all.deb
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
for DIRECTORY in images local-config/skel local-config/backgrounds local-config/bin
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
for DIRECTORY in root share etc/skel etc/skel/working usr/local/bin usr/share/backgrounds/kali
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
wget
curl
build-essential
make
cmake
nasm
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
libglib2.0-dev
libc6-dbg
clang-format
valgrind
shellcheck
strace
ltrace
gdb
ghidra

# essentials
exploitdb
EOF


# custom configs
if [ ! -f kali-build/local-config/skel/.bash_aliases ]
then
	cat > kali-build/local-config/skel/.bash_aliases << EOF
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

if [ ! -f kali-build/local-config/skel/.gdbinit-gef.py ]
then
	wget -O kali-build/local-config/skel/.gdbinit-gef.py -q https://gef.blah.cat/py
	printf "%s" 'source ~/.gdbinit-gef.py' > kali-build/local-config/skel/.gdbinit
fi

if [ ! -f kali-build/local-config/skel/.clang-format ]
then
	curl -s 'https://raw.githubusercontent.com/petertorelli/clang-format-barr-c/master/.clang-format'\
	       	-o kali-build/local-config/skel/.clang-format
fi

# https://mislav.net/2011/12/vim-revisited/
if [ ! -f kali-build/local-config/skel/.vimrc ]
then
	cat > kali-build/local-config/skel/.vimrc << EOF
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
find kali-build/local-config/skel/ -type f -exec cp {} kali-config/common/includes.chroot/root \;
find kali-build/local-config/skel/ -type f -exec cp {} kali-config/common/includes.chroot/etc/skel \;


# custom tools
if [ ! -f kali-build/local-config/bin/anew ]
then
	curl -s -LO 'https://github.com/tomnomnom/anew/releases/download/v0.1.1/anew-linux-386-0.1.1.tgz'
	tar -xvzf 'anew-linux-386-0.1.1.tgz' -C kali-build/local-config/bin/
	rm -f 'anew-linux-386-0.1.1.tgz'
fi
find kali-build/local-config/bin/ -type f -exec cp {} kali-config/common/includes.chroot/usr/local/bin/ \;


# custom wallpapers
if [ ! -f kali-build/local-config/backgrounds/default-background.jpg ]
then
	wget -O kali-build/local-config/backgrounds/default-background.jpg -q \
		'https://www.pixelstalk.net/wp-content/uploads/2016/05/Futuristic-HD-Wallpapers.jpg'
fi
if [ ! -f kali-build/local-config/backgrounds/default-lockscreen.jpg ]
then
	wget -O kali-build/local-config/backgrounds/default-lockscreen.jpg -q \
		'https://www.pixelstalk.net/wp-content/uploads/2016/05/3D-Futuristic-Room-Wallpaper.jpg'
fi
find kali-build/local-config/backgrounds/ -type f -exec cp {} \
	kali-config/common/includes.chroot/usr/share/backgrounds/kali/ \;


# startup actions
cat > kali-config/common/hooks/live/01-my-custom-hooks.chroot << EOF
# change binaries to executable
for BIN in \$(ls -a1 /usr/local/bin/)
do
	chmod +x "/usr/local/bin/\${BIN}"
done

# change default backgrounds
unlink /usr/share/backgrounds/kali-16x9/default
ln -s /usr/share/backgrounds/kali/default-background.jpg /usr/share/backgrounds/kali-16x9/default

unlink /usr/share/desktop-base/kali-theme/login/background
ln -s /usr/share/backgrounds/kali/default-lockscreen.jpg /usr/share/desktop-base/kali-theme/login/background
EOF
chmod +x kali-config/common/hooks/live/01-my-custom-hooks.chroot


# change boot options
sed -i "s|--bootappend-live \"boot=live components quiet splash noeject\"\
|--bootappend-live \"boot=live components quiet nosplash noeject toram systemd.swap=no noautomount nozsh\"\
|g" auto/config

sed -i "s|--bootappend-install \"net.ifnames=0\"\
|--bootappend-install \"boot=live components quiet nosplash noeject toram systemd.swap=no noautomount nozsh\"\
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
isoPath=$(find images/ -name '*.iso'|head -n1)
newIsoPath="kali-build/images/kali-x.iso"
if [ -f "${isoPath}" ]
then
	printf "%s\n" "[*]Moving iso to ${newIsoPath}"
	sudo mv "${isoPath}" "${newIsoPath}"
	sudo chown -R "${CURRENT_USER}:${CURRENT_USER}" kali-build/images/
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

{ printf "%s\n" 'kali-x'; \
	printf "%s\n" '----------------------'; \
	date; date -u; date +%s; \
	printf "\n"; \
	kaliHash=$(md5sum "${isoPath}"); printf "%s\n" "hash: ${kaliHash}"; \
	printf "%s\n" '======================'; } | tee -a kali-build/info.txt

printf "%s\n" '[+]Done!!!'

