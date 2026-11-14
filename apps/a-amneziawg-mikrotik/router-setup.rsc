# ============================================================================
#  router-setup.rsc — разовая подготовка RouterOS для приложения A-amneziawg-mikrotik
#  Идемпотентно: повторный запуск ничего не дублирует.
#
#  Запуск (Winbox -> New Terminal, по одной строке):
#    /tool fetch url="https://aligorov.github.io/routeros-aligorov/apps/a-amneziawg-mikrotik/router-setup.rsc" dst-path=awg-setup.rsc
#    /import awg-setup.rsc
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

# --- 1. Списки интерфейсов (LAN/WAN — стандартные; InAccept включает WAN + veth) ---
:if ([:len [/interface/list/find name="WAN"]] = 0) do={ /interface/list/add name=WAN; :put "+ interface list WAN (добавьте в него WAN-порты!)" }
:if ([:len [/interface/list/find name="LAN"]] = 0) do={ /interface/list/add name=LAN; :put "+ interface list LAN (добавьте в него LAN/bridge!)" }
:if ([:len [/interface/list/find name="InAccept"]] = 0) do={ /interface/list/add name=InAccept include=WAN; :put "+ interface list InAccept" }

# --- 2. veth со статическими адресами (контейнер 192.168.253.2, роутер .1) ---
:if ([:len [/interface/veth/find name="AmneziaWGRoS"]] = 0) do={
  /interface/veth/add name=AmneziaWGRoS address=192.168.253.2/30 gateway=192.168.253.1
  :put "+ veth AmneziaWGRoS (192.168.253.2/30 gw 192.168.253.1)"
}
:if ([:len [/ip/address/find address="192.168.253.1/30"]] = 0) do={
  /ip/address/add address=192.168.253.1/30 interface=AmneziaWGRoS
  :put "+ IP 192.168.253.1/30 на роутере"
}
:if ([:len [/interface/list/member/find interface="AmneziaWGRoS" list="InAccept"]] = 0) do={
  /interface/list/member/add interface=AmneziaWGRoS list=InAccept
  :put "+ AmneziaWGRoS -> InAccept"
}

# --- 3. fasttrack не должен съедать маркированный трафик ---
:do { /ip firewall filter set [find where action=fasttrack-connection] connection-mark=no-mark } on-error={}

# --- 4. Таблица маршрутизации + маршруты (default -> контейнер + blackhole-страховка) ---
:if ([:len [/routing/table/find name="AmneziaWGRoS"]] = 0) do={
  /routing/table/add name=AmneziaWGRoS fib
  :put "+ routing table AmneziaWGRoS"
}
/ip route
:if ([:len [find comment="AmneziaWGRoS_default"]] = 0) do={
  add dst-address=0.0.0.0/0 gateway=192.168.253.2 routing-table=AmneziaWGRoS comment="AmneziaWGRoS_default"
  add blackhole dst-address=0.0.0.0/0 distance=254 routing-table=AmneziaWGRoS comment="AmneziaWGRoS_bh"
  :put "+ default -> 192.168.253.2 в таблицу AmneziaWGRoS (+blackhole fallback)"
}

# --- 5. mangle: выборочная маршрутизация по address-list=AmneziaWGRoS ---
/ip firewall mangle
:if ([:len [find comment="AWG_Accept_no_mark"]] = 0) do={ add action=accept chain=prerouting connection-mark=no-mark connection-state=established comment="AWG_Accept_no_mark"; :put "+ mangle AWG_Accept_no_mark" }
:if ([:len [find comment="AWG_Accept_InAccept"]] = 0) do={ add action=accept chain=prerouting in-interface-list=InAccept comment="AWG_Accept_InAccept"; :put "+ mangle AWG_Accept_InAccept" }
:if ([:len [find comment="AWG_Route_Conn"]] = 0) do={ add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark=AmneziaWGRoS new-routing-mark=AmneziaWGRoS passthrough=no comment="AWG_Route_Conn"; :put "+ mangle AWG_Route_Conn" }
:if ([:len [find comment="AWG_Mark_AddressList"]] = 0) do={ add action=mark-connection chain=prerouting in-interface-list=LAN connection-mark=no-mark connection-state=new dst-address-type=!local dst-address-list=AmneziaWGRoS new-connection-mark=AmneziaWGRoS comment="AWG_Mark_AddressList"; :put "+ mangle AWG_Mark_AddressList" }
:if ([:len [find comment="AWG_Route_New"]] = 0) do={ add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark=AmneziaWGRoS new-routing-mark=AmneziaWGRoS passthrough=no comment="AWG_Route_New"; :put "+ mangle AWG_Route_New" }

# --- 6. DNS: защита от обхода через Apple Private Relay + разрешение remote-requests ---
/ip dns static
:if ([:len [find name="mask.icloud.com"]] = 0) do={ add name="mask.icloud.com" type=NXDOMAIN }
:if ([:len [find name="mask-h2.icloud.com"]] = 0) do={ add name="mask-h2.icloud.com" type=NXDOMAIN }
:if ([:len [find name="doh.dns.apple.com"]] = 0) do={ add name="doh.dns.apple.com" type=NXDOMAIN }
:if ([/ip/dns/get allow-remote-requests] = false) do={ /ip/dns/set allow-remote-requests=yes; :put "+ dns allow-remote-requests=yes" }

# --- 7. Заготовка dst-nat для Server Mode (отключена по умолчанию) ---
/ip firewall nat
:if ([:len [find comment="AWG_Server_DSTNAT"]] = 0) do={
  add action=dst-nat chain=dstnat in-interface-list=WAN protocol=udp dst-port=51821 to-addresses=192.168.253.2 to-ports=51820 disabled=yes comment="AWG_Server_DSTNAT"
  :put "+ dst-nat AWG_Server_DSTNAT (disabled=yes, включите только для Server Mode)"
}

# --- 8. Заготовка Netwatch failover на health-зонд :8081 (отключена по умолчанию) ---
/tool netwatch
:if ([:len [find comment="AWG_Health"]] = 0) do={
  add type=http-get host=192.168.253.2 port=8081 interval=15s disabled=yes comment="AWG_Health" \
    down-script="/ip route disable [find comment=\"AmneziaWGRoS_default\"]" \
    up-script="/ip route enable [find comment=\"AmneziaWGRoS_default\"]"
  :put "+ netwatch AWG_Health (disabled=yes, включите после запуска туннеля)"
}

:put "==="
:put "ГОТОВО. Теперь установите A-amneziawg-mikrotik из App Store (Winbox -> App)."
:put "WebUI после старта: http://<ip-роутера>:8092 или http://192.168.253.2:8080"
:put "DNS внутри туннеля: 192.168.253.2:53 (для /ip/dns/static type=FWD)"
