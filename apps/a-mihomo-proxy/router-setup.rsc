# ============================================================================
#  router-setup.rsc — разовая подготовка RouterOS для приложения A-mihomo-proxy
#  Адаптация официального установщика Medium1992/mihomo-proxy-ros (script21.rsc)
#  Идемпотентно: повторный запуск ничего не дублирует.
#
#  Запуск (Winbox -> New Terminal, по одной строке):
#    /tool fetch url="https://aligorov.github.io/routeros-aligorov/apps/a-mihomo-proxy/router-setup.rsc" dst-path=router-setup.rsc
#    /import router-setup.rsc
# ============================================================================

# --- 0. Проверки ---
:if ([:len [/system/package/find name="container"]] = 0) do={
  :put "ОШИБКА: нет пакета container (System -> Packages)"
  :error "container package required"
}
:if ([/system/device-mode/get container] = false) do={
  :put "ОШИБКА: /system/device-mode/update container=yes (подтвердить кнопкой/питанием)"
  :error "device-mode container required"
}
:put "OK: container package + device-mode"

# --- 1. NAT-фиксы GitHub Fastly (доступ роутера к github.com) ---
:if ([:len [/ip firewall nat find comment="GitHub_Fastly_fix_dstnat"]] = 0) do={
  /ip firewall nat add action=netmap chain=dstnat dst-address=185.199.108.0/22 to-addresses=185.199.109.0/24 comment="GitHub_Fastly_fix_dstnat"
  :put "+ NAT GitHub_Fastly_fix_dstnat"
}
:if ([:len [/ip firewall nat find comment="GitHub_Fastly_fix_output"]] = 0) do={
  /ip firewall nat add action=netmap chain=output dst-address=185.199.108.0/22 to-addresses=185.199.109.0/24 comment="GitHub_Fastly_fix_output"
  :put "+ NAT GitHub_Fastly_fix_output"
}

# --- 2. Списки интерфейсов (LAN/WAN — стандартные; InAccept включает WAN + veth) ---
:if ([:len [/interface/list/find name="WAN"]] = 0) do={ /interface/list/add name=WAN; :put "+ interface list WAN (добавьте в него WAN-порты!)" }
:if ([:len [/interface/list/find name="LAN"]] = 0) do={ /interface/list/add name=LAN; :put "+ interface list LAN (добавьте в него LAN/bridge!)" }
:do { /interface/list/add name=InAccept include=WAN } on-error={}
:do { /interface/list/member/add interface=MihomoProxyRoS list=InAccept } on-error={}

# --- 3. veth со статическими адресами (контейнер 192.168.255.2, роутер .1) ---
:if ([:len [/interface/veth/find name="MihomoProxyRoS"]] = 0) do={
  /interface/veth/add name=MihomoProxyRoS address=192.168.255.2/30 gateway=192.168.255.1
  :put "+ veth MihomoProxyRoS (192.168.255.2/30 gw 192.168.255.1)"
}
:if ([:len [/ip/address/find address="192.168.255.1/30"]] = 0) do={
  /ip/address/add address=192.168.255.1/30 interface=MihomoProxyRoS
  :put "+ IP 192.168.255.1/30 на роутере"
}

# --- 4. fasttrack не должен съедать маркированный трафик ---
:do { /ip firewall filter set [find where action=fasttrack-connection] connection-mark=no-mark } on-error={}

# --- 5. Таблица маршрутизации + маршруты ---
:if ([:len [/routing/table/find name="MihomoProxyRoS"]] = 0) do={
  /routing/table/add name=MihomoProxyRoS fib
  :put "+ routing table MihomoProxyRoS"
}
/ip route
:if ([:len [find comment="MihomoProxyRoS0"]] = 0) do={
  add dst-address=0.0.0.0/0 gateway=192.168.255.2 routing-table=MihomoProxyRoS comment="MihomoProxyRoS0"
  add blackhole comment="MihomoProxyRoS_bh10" distance=254 dst-address=10.0.0.0/8 routing-table=MihomoProxyRoS
  add blackhole comment="MihomoProxyRoS_bh172" distance=254 dst-address=172.16.0.0/12 routing-table=MihomoProxyRoS
  add blackhole comment="MihomoProxyRoS_bh192" distance=254 dst-address=192.168.0.0/16 routing-table=MihomoProxyRoS
  :put "+ default -> 192.168.255.2 в таблицу MihomoProxyRoS (+blackhole приватных)"
}
:if ([:len [find comment="MihomoProxyRoS1"]] = 0) do={
  add dst-address=198.18.0.0/15 gateway=192.168.255.2 comment="MihomoProxyRoS1"
  :put "+ маршрут fake-ip 198.18.0.0/15 -> 192.168.255.2"
}

# --- 6. mangle: маркировка LAN-трафика и маршрутизация в контейнер ---
/ip firewall mangle
:if ([:len [find comment="YT_MSS"]] = 0) do={ add action=change-mss chain=forward dst-address-list=YT in-interface=MihomoProxyRoS new-mss=88 protocol=tcp tcp-flags=syn connection-state=new comment="YT_MSS"; :put "+ mangle YT_MSS" }
:if ([:len [find comment="Accept_no_mark"]] = 0) do={ add action=accept chain=prerouting connection-mark=no-mark connection-state=established comment="Accept_no_mark"; :put "+ mangle 1" }
:if ([:len [find comment="AcceptInWAN&Containers"]] = 0) do={ add action=accept chain=prerouting in-interface-list=InAccept comment="AcceptInWAN&Containers"; :put "+ mangle 2" }
:if ([:len [find comment="RoutingToMihomo2"]] = 0) do={ add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark=MihomoProxyRoS new-routing-mark=MihomoProxyRoS passthrough=no comment="RoutingToMihomo2"; :put "+ mangle 3" }
:if ([:len [find comment="MarkConnAddressList"]] = 0) do={ add action=mark-connection chain=prerouting in-interface-list=LAN connection-mark=no-mark connection-state=new dst-address-list=MihomoProxyRoS new-connection-mark=MihomoProxyRoS comment="MarkConnAddressList"; :put "+ mangle 4" }
:if ([:len [find comment="Discord_RTC"]] = 0) do={ add action=mark-connection chain=prerouting connection-bytes=102 connection-mark=no-mark connection-state=new content="\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00" dst-address-type=!local in-interface-list=LAN new-connection-mark=MihomoProxyRoS dst-port=19294-19344,50000-50100 protocol=udp comment="Discord_RTC"; :put "+ mangle 5" }
:if ([:len [find comment="Discord_WebRTC"]] = 0) do={ add action=mark-connection chain=prerouting connection-bytes=128 connection-mark=no-mark connection-state=new content="\12\A4\42" dst-address-type=!local in-interface-list=LAN new-connection-mark=MihomoProxyRoS dst-port=19294-19344,50000-50100 protocol=udp comment="Discord_WebRTC"; :put "+ mangle 6" }
:if ([:len [find comment="RoutingToMihomo1"]] = 0) do={ add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark=MihomoProxyRoS new-routing-mark=MihomoProxyRoS passthrough=no comment="RoutingToMihomo1"; :put "+ mangle 7" }

# --- 7. DNS: DNS-маскировка Apple (не ломать fake-ip) + Twitch через mihomo ---
/ip dns static
:if ([:len [find name="mask.icloud.com"]] = 0) do={ add name="mask.icloud.com" type=NXDOMAIN }
:if ([:len [find name="mask-h2.icloud.com"]] = 0) do={ add name="mask-h2.icloud.com" type=NXDOMAIN }
:if ([:len [find name="doh.dns.apple.com"]] = 0) do={ add name="doh.dns.apple.com" type=NXDOMAIN }
:if ([:len [find name="usher.ttvnw.net"]] = 0) do={ add comment=twitch forward-to=MihomoProxyRoS match-subdomain=yes name=usher.ttvnw.net type=FWD }
:if ([:len [find name="gql.twitch.tv"]] = 0) do={ add comment=twitch forward-to=MihomoProxyRoS match-subdomain=yes name=gql.twitch.tv type=FWD }
:if ([/ip/dns/get allow-remote-requests] = false) do={ /ip/dns/set allow-remote-requests=yes; :put "+ dns allow-remote-requests=yes" }

# --- 8. Первичные address-list (что гонять через прокси) ---
/ip firewall address-list
:do { add list=YT comment=YT_MSS address=www.youtube.com } on-error={}
:do { add list=MihomoProxyRoS comment=YT address=www.youtube.com } on-error={}
:do { add list=MihomoProxyRoS comment=NTCParty address=ntc.party } on-error={}

:put "==="
:put "ГОТОВО. Теперь установите A-mihomo-proxy из App Store (Winbox -> App)."
:put "Панель после старта: http://<ip-роутера>:8090 (admin/admin) или http://192.168.255.2:80"
