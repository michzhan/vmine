#!/bin/bash

#================================================================
#    System Request:Debian 9+ (Ubuntu 18.04+/Centos 7+ not test)
#    Dscription: V2ray ws+tls onekey
#   Reference:
#       https://github.com/wulabing/V2Ray_ws-tls_bash_onekey
#       https://github.com/dylanbai8/V2Ray_ws-tls_Website_onekey
#================================================================


#fonts color
Green="\033[32m" 
Red="\033[31m" 
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

v2ray_conf_dir="/etc/v2ray"
nginx_conf_dir="/etc/nginx/conf.d"
v2ray_conf="${v2ray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_dir="/etc/nginx"
nginx_openssl_src="/usr/local/src"
nginx_version="1.16.1"
openssl_version="1.1.1d"
pcre_version="8.43"
zlib_version="1.2.11"

#生成伪装路径
random_number(){
    let PORT=$RANDOM+10000
    UUID=$(cat /proc/sys/kernel/random/uuid)
    camouflage=`cat /dev/urandom | head -n 10 | md5sum | head -c 8`
    hostheader=`cat /dev/urandom | head -n 10 | md5sum | head -c 8`
}

#从VERSION中提取发行版系统的英文名称，为了在debian/ubuntu下添加相对应的Nginx apt源
source /etc/os-release
VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`

judge(){
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败${Font}"
        exit 1
    fi
}

is_root(){
    if [ `id -u` == 0 ]
        then echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}" 
        exit 1
    fi
}

check_system(){
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
    elif [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 16 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        $INS update
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi

    systemctl stop firewalld && systemctl disable firewalld
    echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"
}

dependency_install(){
    ${INS} install -y wget git lsof bc unzip qrencode curl gnupg2 ca-certificates lsb-release build-essential tree

    if [[ "${ID}" == "centos" ]];then
       ${INS} -y install crontabs
    else
       ${INS} -y install cron
    fi
    judge "安装 crontab"

    if [[ "${ID}" == "centos" ]];then
        ${INS} install socat nc -y        
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    if [[ "${ID}" == "centos" ]];then
       touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
       systemctl start crond && systemctl enable crond
    else
       if [[ -f "/var/spool/cron/crontabs/root" ]];then
           # Do nothing
       echo ""
       else
           touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
           systemctl start cron && systemctl enable cron
       fi

    fi
    #judge "crontab 自启动配置 "


    # if [[ "${ID}" == "centos" ]];then
    #    ${INS} -y groupinstall "Development tools"
    # else
    #    ${INS} -y install build-essential
    # fi
    # judge "编译工具包 安装"

    # if [[ "${ID}" == "centos" ]];then
    #    ${INS} -y install pcre pcre-devel zlib-devel
    # else
    #    ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev
    # fi


    # judge "nginx 编译依赖安装"

}

chrony_install(){
    ${INS} -y install chrony
    judge "安装 chrony 时间同步服务 "

    timedatectl set-ntp true

    if [[ "${ID}" == "centos" ]];then
       systemctl enable chronyd && systemctl restart chronyd
    else
       systemctl enable chrony && systemctl restart chrony
    fi

    judge "chronyd 启动 "

    timedatectl set-timezone Asia/Shanghai

    echo -e "${OK} ${GreenBG} 等待时间同步 ${Font}"
    sleep 10

    chronyc sourcestats -v
    chronyc tracking -v
    date
    sleep 10
    echo ""
    #x read -p "请确认时间是否准确,误差范围±3分钟(Y/N): " chrony_install
    #x [[ -z ${chrony_install} ]] && chrony_install="Y"
    #x case $chrony_install in
    #x     [yY][eE][sS]|[yY])
    #x         echo -e "${GreenBG} 继续安装 ${Font}"
    #x         sleep 2
    #x         ;;
    #x     *)
    #x         echo -e "${RedBG} 安装终止 ${Font}"
    #x         exit 2
    #x         ;;
    #x     esac
}

basic_optimization(){
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >> /etc/security/limits.conf
    echo '* hard nofile 65536' >> /etc/security/limits.conf

    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]];then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}


domain_check(){
    domain_ip=`ping ${domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
    local_ip=`curl -4 ip.sb`
    echo -e "域名dns解析IP：${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ $(echo ${local_ip}|tr '.' '+'|bc) -eq $(echo ${domain_ip}|tr '.' '+'|bc) ]];then
        echo -e "${OK} ${GreenBG} 域名dns解析IP  与 本机IP 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 请确保域名添加了正确的 A 记录，否则将无法正常使用 V2ray"
        echo -e "${Error} ${RedBG} 域名dns解析IP 与 本机IP 不匹配 是否继续安装？（y/n）${Font}" && read install
        case $install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} 继续安装 ${Font}" 
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}" 
            exit 2
            ;;
        esac
    fi
}

port_alterid_set(){
    echo -e "${Info} ${GreenBG} 【配置 1/3 】请输入你的域名信息(如:www.bing.com)，请确保域名A记录已正确解析至服务器IP ${Font}"
    read -p "请输入：" domain
    echo -e "${Info} ${GreenBG} 【配置 2/3 】请输入连接端口（默认:443 无特殊需求请直接按回车键） ${Font}"
    read -p "请输入：" port
    [[ -z ${port} ]] && port="443"
    echo -e "${Info} ${GreenBG} 【配置 3/3 】请输入alterID（默认:16 无特殊需求请直接按回车键） ${Font}"
    read -p "请输入：" alterID
    [[ -z ${alterID} ]] && alterID="16"
    echo -e "----------------------------------------------------------"
    echo -e "${Info} ${GreenBG} 你输入的配置信息为 域名：${domain} 端口：${port} alterID：${alterID} ${Font}"
    echo -e "----------------------------------------------------------"
}

port_exist_check(){
    if [[ 0 -eq `lsof -i:"$1" | grep -i "listen" | wc -l` ]];then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}


nginx_install(){
    # 使用repo安装
    ## http://nginx.org/en/linux_packages.html
    echo "deb http://nginx.org/packages/mainline/debian `lsb_release -cs` nginx" | tee /etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
    echo -e "${OK} ${GreenBG} 添加 Nginx apt源 成功 ${Font}"
    
    ${INS} update
    ${INS} install nginx -y
    if [[ -d /etc/nginx ]];then
        echo -e "${OK} ${GreenBG} nginx 安装完成 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} nginx 安装失败 ${Font}"
        exit 5
    fi

    # 修改基本配置
    #sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/nginx.conf
    #sed -i '$i include conf.d/*.conf;' ${nginx_dir}/nginx.conf

    # 添加配置文件夹，适配旧版脚本
    #x mkdir -p ${nginx_dir}/conf/conf.d
}

v2ray_install(){
    if [[ -d /root/v2ray ]];then
        rm -rf /root/v2ray
    fi
    if [[ -d /etc/v2ray ]];then
        rm -rf /etc/v2ray
    fi
    mkdir -p /root/v2ray && cd /root/v2ray
    wget  --no-check-certificate https://install.direct/go.sh

    ## wget http://install.direct/go.sh
    
    if [[ -f go.sh ]];then
        bash go.sh --force
        judge "安装 V2ray"
    else
        echo -e "${Error} ${RedBG} V2ray 安装文件下载失败，请检查下载地址是否可用 ${Font}"
        exit 4
    fi
    # 清除临时文件
    rm -rf /root/v2ray
}

modify_port_UUID(){
    sed -i "/\"port\"/c  \    \"port\":${PORT}," ${v2ray_conf}
    sed -i "/\"id\"/c \\\t  \"id\":\"${UUID}\"," ${v2ray_conf}
    sed -i "/\"alterId\"/c \\\t  \"alterId\":${alterID}" ${v2ray_conf}
    sed -i "/\"path\"/c \\\t  \"path\":\"\/${camouflage}\/\"" ${v2ray_conf}
}

modify_nginx(){
    sed -i "1,/listen/{s/listen 443 ssl;/listen ${port} ssl;/}" ${nginx_conf}
    sed -i "/server_name/c \\\tserver_name ${domain};" ${nginx_conf}
    sed -i "/location/c \\\tlocation \/${camouflage}\/" ${nginx_conf}
    sed -i "/proxy_pass/c \\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
    sed -i "/return/c \\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}

    sed -i "27i proxy_intercept_errors on;"  ${nginx_dir}/conf/nginx.conf
    sed -i "/proxy_intercept_errors/s/^/    /" ${nginx_dir}/conf/nginx.conf
}

nginx_conf_add(){
    touch ${nginx_conf_dir}/v2ray.conf
    cat>${nginx_conf_dir}/v2ray.conf<<EOF
    server {
        listen 443 ssl;
        ssl_certificate       /data/v2ray.crt;
        ssl_certificate_key   /data/v2ray.key;
        ssl_protocols         TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 30m;
        add_header Strict-Transport-Security "max-age=31536000";
        server_name           serveraddr.com;
        index index.html index.htm;
        root  /www;
        error_page 400 = /400.html;
        location /ray/ 
        {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        }
    }
    server {
        listen 80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

modify_nginx
judge "Nginx 配置修改"

}

v2ray_conf_add(){
    cd /etc/v2ray
    wget https://raw.githubusercontent.com/michzhan/vmine/master/config/config.json -O config.json
    modify_port_UUID
    judge "V2ray 配置修改"
}

web_camouflage(){
    ##请注意 这里和LNMP脚本的默认路径冲突，千万不要在安装了LNMP的环境下使用本脚本，否则后果自负
    #x rm -rf /home/wwwroot && mkdir -p /home/wwwroot && cd /home/wwwroot
    #x git clone https://github.com/eyebluecn/levis.git
    #x judge "web 站点伪装"   
    cd ~
    wget --no-check-certificate https://github.com/michzhan/vmine/raw/master/web/webpages.tar.gz
    tar zxvf webpages.tar.gz
    rm -rf /www
    cp -r ~/webpages /www
    
    chgrp -R nginx /www
    chown -R nginx /www
    chmod -R g-w /www
    chmod -R o-w /www
    chmod -R o-x /www   
}



acme(){
    cd ~
    curl  https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"

    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --force
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
        sleep 2
        mkdir /data
        ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
        sleep 2
        fi
    else
        echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
        exit 1
    fi
}

ssl_judge_and_install(){
    if [[ -f "/data/v2ray.key" && -f "/data/v2ray.crt" ]];then
        echo "证书文件已存在"
    elif [[ -f "~/.acme.sh/${domain}_ecc/${domain}.key" && -f "~/.acme.sh/${domain}_ecc/${domain}.cer" ]];then
        echo "证书文件已存在"
        ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        judge "证书应用"
    else
        acme
    fi
}

# nginx 源代码安装
nginx_build_install(){
    if [[ -d "/etc/nginx" ]];then
        rm -rf /etc/nginx
    fi

    wget -nc http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "Nginx 下载"
    wget -nc https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "openssl 下载"
    
    wget -nc https://ftp.pcre.org/pub/pcre/pcre-${pcre_version}.tar.gz -P ${nginx_openssl_src}
    https://ftp.pcre.org/pub/pcre/pcre-8.42.tar.gz
    judge "pcre 下载"
    wget -nc https://www.zlib.net/zlib-${zlib_version}.tar.gz -P ${nginx_openssl_src}
    judge "pcre 下载"
    
    
    cd ${nginx_openssl_src}

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz
    
    [[ -d pcre-"$pcre_version" ]] && rm -rf pcre-"$pcre_version"
    tar -zxvf pcre-"$pcre_version".tar.gz
    
    [[ -d zlib-"$zlib_version" ]] && rm -rf zlib-"$zlib_version"
    tar -zxvf zlib-"$zlib_version".tar.gz
    
    

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} 即将开始编译安装 Nginx, 过程稍久，请耐心等待 ${Font}"
    sleep 4

    cd nginx-${nginx_version}
    ./configure --prefix="${nginx_dir}"                         \
            --with-http_ssl_module                              \
            --with-http_gzip_static_module                      \
            --with-http_stub_status_module                      \
            --with-http_realip_module                           \
            --with-http_flv_module                              \
            --with-http_mp4_module                              \
            --with-http_secure_link_module                      \
            --with-http_v2_module                               \
            --with-pcre=../pcre-"$pcre_version"                 \
            --with-zlib=../zlib-"zlib_version"                  \
            --with-openssl=../openssl-"$openssl_version"
            
    judge "编译检查"
    make && make install
    judge "Nginx 编译安装"

    # 修改基本配置
    #sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    #sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf



    # 删除临时文件
    rm -rf nginx-"${nginx_version}"
    rm -rf openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    # 添加配置文件夹，适配旧版脚本
    mkdir -p ${nginx_dir}/conf/conf.d
}


# nginx_systemd仅源码安装才使用
nginx_systemd(){
    cat>/lib/systemd/system/nginx.service<<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

judge "Nginx systemd ServerFile 添加"
}


show_information(){
    clear
    cd ~

    echo -e "${OK} ${Green} V2ray+ws+tls 安装成功" >./v2ray_info.txt
    echo -e "${Red} V2ray 配置信息 ${Font}" >>./v2ray_info.txt
    echo -e "${Red} 地址（address）:${Font} ${domain} " >>./v2ray_info.txt
    echo -e "${Red} 端口（port）：${Font} ${port} " >>./v2ray_info.txt
    echo -e "${Red} 用户id（UUID）：${Font} ${UUID}" >>./v2ray_info.txt
    echo -e "${Red} 额外id（alterId）：${Font} ${alterID}" >>./v2ray_info.txt
    echo -e "${Red} 加密方式（security）：${Font} 自适应 " >>./v2ray_info.txt
    echo -e "${Red} 传输协议（network）：${Font} ws " >>./v2ray_info.txt
    echo -e "${Red} 伪装类型（type）：${Font} none " >>./v2ray_info.txt
    echo -e "${Red} 路径（不要落下/）：${Font} /${camouflage}/ " >>./v2ray_info.txt
    echo -e "${Red} 底层传输安全：${Font} tls " >>./v2ray_info.txt
    cat ./v2ray_info.txt

}

start_process_systemd(){
    ### nginx服务在安装完成后会自动启动。需要通过restart或reload重新加载配置
    systemctl restart nginx
    judge "Nginx 启动"

    systemctl enable nginx
    judge "设置 Nginx 开机自启"

    systemctl restart v2ray
    judge "V2ray 启动"

    systemctl enable v2ray
    judge "设置 v2ray 开机自启"
}


main(){
    is_root
    port_alterid_set
    random_number
    check_system
    dependency_install
    chrony_install
    basic_optimization
    domain_check
    port_exist_check 80
    port_exist_check ${port}
    nginx_install
    #nginx_build_install
    v2ray_install
    nginx_conf_add
    v2ray_conf_add
    web_camouflage

    ssl_judge_and_install
    #nginx_systemd
    show_information
    start_process_systemd
}

#main
