package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ROSSchemaCheck struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	OK     bool   `json:"ok"`
	Warn   bool   `json:"warn,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type ROSSchemaReport struct {
	OK          bool             `json:"ok"`
	Mode        string           `json:"mode"`
	ContainerIP string           `json:"container_ip"`
	PeerIP      string           `json:"peer_ip,omitempty"`
	AddressList string           `json:"address_list"`
	RouteTable  string           `json:"route_table"`
	Checks      []ROSSchemaCheck `json:"checks"`
	Warnings    []string         `json:"warnings,omitempty"`
	CLIScript   string           `json:"cli_script"`
	Error       string           `json:"error,omitempty"`
}

type ROSProvisionOptions struct {
	SetupDNS   bool   `json:"setup_dns"`
	RouteTable string `json:"route_table,omitempty"`
}

type ROSProvisionResult struct {
	OK      bool            `json:"ok"`
	Applied []string        `json:"applied,omitempty"`
	Report  ROSSchemaReport `json:"report"`
	Error   string          `json:"error,omitempty"`
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func rosURLHost(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return ""
}

func (c *ROSClient) rosPrint(ctx context.Context, conn rosConnConfig, path string, proplist []string, query ...string) ([]map[string]any, error) {
	if binCfg, ok := canUseBinAPI(conn); ok && c.binSync != nil {
		var args []string
		for _, q := range query {
			args = append(args, "?"+q)
		}
		if len(proplist) > 0 {
			args = append(args, "=.proplist="+strings.Join(proplist, ","))
		}
		rows, err := c.binSync.Exec(ctx, binCfg, path+"/print", args...)
		if err == nil {
			out := make([]map[string]any, 0, len(rows))
			for _, r := range rows {
				m := make(map[string]any, len(r))
				for k, v := range r {
					m[k] = v
				}
				out = append(out, m)
			}
			return out, nil
		}
		if !isBinTransportFallbackErr(err) || conn.baseURL == "" {
			return nil, err
		}
	}
	if conn.baseURL == "" {
		return nil, errors.New("RouterOS REST URL is not configured")
	}
	return c.listResources(conn, path, proplist, query)
}

func (c *ROSClient) rosAdd(ctx context.Context, conn rosConnConfig, path string, fields map[string]string) error {
	if binCfg, ok := canUseBinAPI(conn); ok && c.binSync != nil {
		args := make([]string, 0, len(fields))
		for k, v := range fields {
			args = append(args, "="+k+"="+v)
		}
		_, err := c.binSync.Exec(ctx, binCfg, path+"/add", args...)
		if err == nil || !isBinTransportFallbackErr(err) || conn.baseURL == "" {
			return err
		}
	}
	if conn.baseURL == "" {
		return errors.New("RouterOS REST URL is not configured")
	}
	payload := make(map[string]any, len(fields))
	for k, v := range fields {
		payload[k] = v
	}
	_, _, err := c.doWithConn(conn, http.MethodPut, path, payload)
	return err
}

func (c *ROSClient) rosSet(ctx context.Context, conn rosConnConfig, path, id string, fields map[string]string) error {
	if binCfg, ok := canUseBinAPI(conn); ok && c.binSync != nil {
		args := make([]string, 0, 1+len(fields))
		if id != "" {
			args = append(args, "=.id="+id)
		}
		for k, v := range fields {
			args = append(args, "="+k+"="+v)
		}
		_, err := c.binSync.Exec(ctx, binCfg, path+"/set", args...)
		if err == nil || !isBinTransportFallbackErr(err) || conn.baseURL == "" {
			return err
		}
	}
	if conn.baseURL == "" {
		return errors.New("RouterOS REST URL is not configured")
	}
	payload := make(map[string]any, len(fields))
	for k, v := range fields {
		payload[k] = v
	}
	if id == "" {
		_, _, err := c.doWithConn(conn, http.MethodPost, path+"/set", payload)
		return err
	}
	_, _, err := c.doWithConn(conn, http.MethodPatch, path+"/"+id, payload)
	return err
}

func (c *ROSClient) rosMoveBefore(ctx context.Context, conn rosConnConfig, path, id, destID string) error {
	if id == "" || destID == "" || id == destID {
		return nil
	}
	if binCfg, ok := canUseBinAPI(conn); ok && c.binSync != nil {
		_, err := c.binSync.Exec(ctx, binCfg, path+"/move", "=numbers="+id, "=destination="+destID)
		if err == nil || !isBinTransportFallbackErr(err) || conn.baseURL == "" {
			return err
		}
	}
	if conn.baseURL == "" {
		return errors.New("RouterOS REST URL is not configured")
	}
	_, _, err := c.doWithConn(conn, http.MethodPost, path+"/move", map[string]any{
		"numbers":     id,
		"destination": destID,
	})
	return err
}

func rosAddrMatchPrefixOrIP(raw, wantIP string) bool {
	s := strings.TrimSpace(raw)
	if s == wantIP {
		return true
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		if a, err2 := netip.ParseAddr(wantIP); err2 == nil {
			return pfx.Addr() == a
		}
	}
	return false
}

// BuildROSSchemaCLIScript produces a copyable idempotent RouterOS v7 Terminal script
// matching the chosen ros_mode and active container parameters.
func BuildROSSchemaCLIScript(s AppSettings, containerIP, peerIP string) string {
	mode := normalizeROSMode(s.ROSMode)
	if containerIP == "" {
		containerIP = defaultROSContainerIP
	}
	listName := firstNonEmpty(s.ROSAddressList, "AmneziaWGRoS")
	tableName := firstNonEmpty(s.ROSRouteTable, "AmneziaWGRoS")
	if tableName == "main" {
		tableName = "AmneziaWGRoS"
	}
	bgpTable := firstNonEmpty(s.ROSBGPRouteTable, "main")
	localAS := s.ROSBGPLocalAS
	if localAS == 0 {
		localAS = 65511
	}
	remoteAS := s.ROSBGPRemoteAS
	if remoteAS == 0 {
		remoteAS = 65510
	}
	_ = peerIP

	switch mode {
	case ROSModeAddressList:
		return fmt.Sprintf(`# === Режим: Address-List + Mangle + Route -> в контейнер (%s) ===
/interface/list
:if ([:len [find name="LAN"]] = 0) do={ add name=LAN }
/routing/table
:if ([:len [find name="%s"]] = 0) do={ add name="%s" fib }
/ip/route
:if ([:len [find comment="AmneziaWGRoS_default"]] = 0) do={
  add dst-address=0.0.0.0/0 gateway=%s routing-table="%s" comment="AmneziaWGRoS_default"
} else={
  set [find comment="AmneziaWGRoS_default"] gateway=%s routing-table="%s" disabled=no
}
:if ([:len [find comment="AmneziaWGRoS_bh"]] = 0) do={
  add blackhole dst-address=0.0.0.0/0 distance=254 routing-table="%s" comment="AmneziaWGRoS_bh"
}
:do { /ip/firewall/filter set [find where action=fasttrack-connection] connection-mark=no-mark } on-error={}
/ip/firewall/mangle
:if ([:len [find comment="AWG_Accept_Container"]] = 0) do={ add action=accept chain=prerouting src-address=%s comment="AWG_Accept_Container" } else={ set [find comment="AWG_Accept_Container"] src-address=%s disabled=no }
:if ([:len [find comment="AWG_Accept_no_mark"]] = 0) do={ add action=accept chain=prerouting connection-mark=no-mark connection-state=established comment="AWG_Accept_no_mark" }
:if ([:len [find comment="AWG_Route_Conn"]] = 0) do={ add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark="%s" new-routing-mark="%s" passthrough=no comment="AWG_Route_Conn" }
:if ([:len [find comment="AWG_Mark_AddressList"]] = 0) do={ add action=mark-connection chain=prerouting in-interface-list=LAN connection-mark=no-mark connection-state=new dst-address-type=!local dst-address-list="%s" new-connection-mark="%s" comment="AWG_Mark_AddressList" }
:if ([:len [find comment="AWG_Route_New"]] = 0) do={ add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark="%s" new-routing-mark="%s" passthrough=no comment="AWG_Route_New" }`,
			containerIP, tableName, tableName,
			containerIP, tableName, containerIP, tableName, tableName,
			containerIP, containerIP,
			tableName, tableName,
			listName, tableName,
			tableName, tableName,
		)

	case ROSModeBGP:
		role := "ebgp"
		if localAS == remoteAS {
			role = "ibgp"
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("# === Режим: BGP (без mangle, FastTrack остаётся включённым, peer=%s) ===\n", containerIP))
		if bgpTable != "main" {
			b.WriteString(fmt.Sprintf("/routing/table\n:if ([:len [find name=\"%s\"]] = 0) do={ add name=\"%s\" fib }\n", bgpTable, bgpTable))
		}
		b.WriteString(`/routing/filter/rule
:if ([:len [find chain="awg-bgp-in" comment="awg-ctl:bgp-in"]] = 0) do={
  add chain="awg-bgp-in" rule="if (dst in 0.0.0.0/0 && dst-len > 0) { accept }" comment="awg-ctl:bgp-in"
}
/routing/bgp/connection
`)
		b.WriteString(fmt.Sprintf(`:if ([:len [find name="awg-ctl-bgp"]] = 0) do={
  add name="awg-ctl-bgp" as=%d remote.address=%s/32 remote.as=%d local.role=%s connect=no listen=yes routing-table="%s" input.filter="awg-bgp-in" comment="awg-ctl:bgp"
} else={
  set [find name="awg-ctl-bgp"] as=%d remote.address=%s/32 remote.as=%d local.role=%s connect=no listen=yes routing-table="%s" input.filter="awg-bgp-in" disabled=no
}`,
			remoteAS, containerIP, localAS, role, bgpTable,
			remoteAS, containerIP, localAS, role, bgpTable,
		))
		return b.String()

	case ROSModeGateway:
		return fmt.Sprintf(`# === Режим: Весь трафик LAN через контейнер (%s) ===
/interface/list
:if ([:len [find name="LAN"]] = 0) do={ add name=LAN }
/routing/table
:if ([:len [find name="%s"]] = 0) do={ add name="%s" fib }
/ip/route
:if ([:len [find comment="AmneziaWGRoS_default"]] = 0) do={
  add dst-address=0.0.0.0/0 gateway=%s routing-table="%s" comment="AmneziaWGRoS_default"
} else={
  set [find comment="AmneziaWGRoS_default"] gateway=%s routing-table="%s" disabled=no
}
:if ([:len [find comment="AmneziaWGRoS_bh"]] = 0) do={
  add blackhole dst-address=0.0.0.0/0 distance=254 routing-table="%s" comment="AmneziaWGRoS_bh"
}
:do { /ip/firewall/filter set [find where action=fasttrack-connection] connection-mark=no-mark } on-error={}
/ip/firewall/mangle
:if ([:len [find comment="AWG_Accept_Container"]] = 0) do={ add action=accept chain=prerouting src-address=%s comment="AWG_Accept_Container" }
:if ([:len [find comment="AWG_GW_Bypass_10"]] = 0) do={ add action=accept chain=prerouting in-interface-list=LAN dst-address=10.0.0.0/8 comment="AWG_GW_Bypass_10" }
:if ([:len [find comment="AWG_GW_Bypass_172"]] = 0) do={ add action=accept chain=prerouting in-interface-list=LAN dst-address=172.16.0.0/12 comment="AWG_GW_Bypass_172" }
:if ([:len [find comment="AWG_GW_Bypass_192"]] = 0) do={ add action=accept chain=prerouting in-interface-list=LAN dst-address=192.168.0.0/16 comment="AWG_GW_Bypass_192" }
:if ([:len [find comment="AWG_Route_Conn"]] = 0) do={ add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark="%s" new-routing-mark="%s" passthrough=no comment="AWG_Route_Conn" }
:if ([:len [find comment="AWG_GW_Mark_All"]] = 0) do={ add action=mark-connection chain=prerouting in-interface-list=LAN connection-mark=no-mark connection-state=new dst-address-type=!local new-connection-mark="%s" comment="AWG_GW_Mark_All" }
:if ([:len [find comment="AWG_Route_New"]] = 0) do={ add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark="%s" new-routing-mark="%s" passthrough=no comment="AWG_Route_New" }
# Для полной прозрачности укажите DNS роутера/клиентов -> %s (или настройте DHCP DNS = %s)`,
			containerIP, tableName, tableName,
			containerIP, tableName, containerIP, tableName, tableName,
			containerIP,
			tableName, tableName,
			tableName,
			tableName, tableName,
			containerIP, containerIP,
		)

	default:
		tbl := firstNonEmpty(s.ROSRouteTable, "main")
		var b strings.Builder
		b.WriteString(fmt.Sprintf("# === Режим: Ручной (domains.txt + AllowedIPs, gw=%s, table=%s) ===\n", containerIP, tbl))
		if tbl != "main" {
			b.WriteString(fmt.Sprintf("/routing/table\n:if ([:len [find name=\"%s\"]] = 0) do={ add name=\"%s\" fib }\n", tbl, tbl))
		}
		b.WriteString("/ip/dns/set allow-remote-requests=yes\n")
		b.WriteString(fmt.Sprintf("# Прописываемые /ip/route и /ip/dns/static (type=FWD -> %s) управляются автоматически при включённых опциях синхронизации.", containerIP))
		return b.String()
	}
}

func (c *ROSClient) snapshotSettingsForSchema(s AppSettings, opts *ROSProvisionOptions) (rosConnConfig, AppSettings, string, string, string) {
	conn := c.connSnapshot()
	if s.ROSMode == "" {
		s.ROSMode = conn.mode
	}
	if s.ROSContainerIP == "" {
		s.ROSContainerIP = conn.gatewayIP
	}
	if s.ROSAddressList == "" {
		s.ROSAddressList = conn.addrList
	}
	if s.ROSRouteTable == "" {
		s.ROSRouteTable = conn.routeTable
	}
	if s.ROSBGPLocalAS == 0 {
		s.ROSBGPLocalAS = conn.bgpLocalAS
	}
	if s.ROSBGPRemoteAS == 0 {
		s.ROSBGPRemoteAS = conn.bgpRemoteAS
	}
	if s.ROSBGPPeerIP == "" {
		s.ROSBGPPeerIP = conn.bgpPeerIP
	}
	if s.ROSBGPRouteTable == "" {
		s.ROSBGPRouteTable = conn.bgpRouteTable
	}
	mode := normalizeROSMode(s.ROSMode)
	listName := firstNonEmpty(s.ROSAddressList, "AmneziaWGRoS")
	tableName := firstNonEmpty(s.ROSRouteTable, "AmneziaWGRoS")
	if opts != nil && strings.TrimSpace(opts.RouteTable) != "" {
		tableName = strings.TrimSpace(opts.RouteTable)
	}
	if mode != ROSModeManual && mode != ROSModeBGP && tableName == "main" {
		tableName = "AmneziaWGRoS"
	}
	if mode == ROSModeBGP {
		tableName = firstNonEmpty(s.ROSBGPRouteTable, "main")
	}
	return conn, s, mode, listName, tableName
}

// isContainerLoopGuardRule returns (true, viaIface) when a prerouting accept rule
// shields return traffic from the container (either by gateway src-address or
// an explicit container/InAccept ingress interface match).
func isContainerLoopGuardRule(r map[string]any, gatewayIP string) (ok bool, viaIface bool) {
	if strField(r, "action") != "accept" {
		return false, false
	}
	if rosAddrMatchPrefixOrIP(strField(r, "src-address"), gatewayIP) {
		return true, false
	}
	cmt := strField(r, "comment")
	inList := strField(r, "in-interface-list")
	inIface := strField(r, "in-interface")
	if strings.EqualFold(inList, "InAccept") || cmt == "AWG_Accept_InAccept" {
		return true, true
	}
	if strings.HasPrefix(cmt, "AWG_Accept_") && cmt != "AWG_Accept_Container" && cmt != "AWG_Accept_no_mark" &&
		((inList != "" && !strings.EqualFold(inList, "LAN")) || inIface != "") {
		return true, true
	}
	if inIface != "" {
		lower := strings.ToLower(inIface)
		if strings.Contains(lower, "docker") || strings.Contains(lower, "veth") {
			return true, true
		}
	}
	return false, false
}

// isMarkOrRouteRuleForTable reports whether a prerouting mangle rule belongs to
// the schema's connection-marking or policy-routing pipeline for listName/tableName.
func isMarkOrRouteRuleForTable(r map[string]any, mode, listName, tableName string) bool {
	act := strField(r, "action")
	cmt := strField(r, "comment")
	switch act {
	case "mark-routing":
		return (tableName != "" && strField(r, "new-routing-mark") == tableName) ||
			cmt == "AWG_Route_Conn" || cmt == "AWG_Route_New"
	case "mark-connection":
		if mode == ROSModeGateway && cmt == "AWG_GW_Mark_All" && strField(r, "new-connection-mark") != "" {
			return true
		}
		if listName != "" && strField(r, "dst-address-list") == listName && strField(r, "new-connection-mark") != "" {
			return true
		}
		return cmt == "AWG_Mark_AddressList" || (tableName != "" && strField(r, "new-connection-mark") == tableName)
	default:
		return false
	}
}

// InspectSchema inspects the RouterOS configuration for the active ros_mode
// without mutating router state.
func (c *ROSClient) InspectSchema(s AppSettings) ROSSchemaReport {
	conn, normS, mode, listName, tableName := c.snapshotSettingsForSchema(s, nil)
	peerIP := firstNonEmpty(conn.bgpPeerIP, rosURLHost(conn.baseURL))
	report := ROSSchemaReport{
		Mode:        mode,
		ContainerIP: conn.gatewayIP,
		PeerIP:      peerIP,
		AddressList: listName,
		RouteTable:  tableName,
		CLIScript:   BuildROSSchemaCLIScript(normS, conn.gatewayIP, peerIP),
	}

	if conn.baseURL == "" && !(conn.useBinAPI && conn.binCfg.Addr != "") {
		report.Error = "RouterOS не настроен (укажите ROS_URL и учётные данные)"
		return report
	}
	if conn.urlErr != "" {
		report.Error = conn.urlErr
		return report
	}
	if conn.user == "" {
		report.Error = "Не указан ROS_USER"
		return report
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	// Helper to inspect fasttrack filter rule.
	checkFasttrack := func() ROSSchemaCheck {
		rows, err := c.rosPrint(ctx, conn, "/ip/firewall/filter", []string{".id", "action", "connection-mark", "disabled"})
		if err != nil {
			return ROSSchemaCheck{Key: "fasttrack", Title: "FastTrack compat", OK: false, Warn: true, Detail: err.Error()}
		}
		var badCount, totalFT int
		for _, r := range rows {
			if isTruthyROS(r["disabled"]) || strField(r, "action") != "fasttrack-connection" {
				continue
			}
			totalFT++
			if strings.TrimSpace(strField(r, "connection-mark")) == "" {
				badCount++
			}
		}
		if totalFT == 0 {
			return ROSSchemaCheck{Key: "fasttrack", Title: "FastTrack не мешает трафику", OK: true, Detail: "активный fasttrack-connection не найден"}
		}
		if badCount > 0 {
			return ROSSchemaCheck{
				Key:    "fasttrack",
				Title:  "FastTrack требует connection-mark=no-mark",
				OK:     false,
				Warn:   true,
				Detail: fmt.Sprintf("%d правил(а) fasttrack-connection без connection-mark=no-mark — маркированные соединения будут обходить контейнер", badCount),
			}
		}
		return ROSSchemaCheck{Key: "fasttrack", Title: "FastTrack с connection-mark=no-mark", OK: true, Detail: fmt.Sprintf("проверено правил: %d", totalFT)}
	}

	// Helper to check LAN interface-list members (never silently alters port membership).
	checkLANMembers := func() ROSSchemaCheck {
		members, err := c.rosPrint(ctx, conn, "/interface/list/member", []string{".id", "list", "interface", "disabled"}, "list=LAN")
		if err != nil {
			return ROSSchemaCheck{Key: "lan_list", Title: "Список интерфейсов LAN", OK: false, Warn: true, Detail: err.Error()}
		}
		var active []string
		for _, m := range members {
			if isTruthyROS(m["disabled"]) {
				continue
			}
			if list := strField(m, "list"); list == "" || list == "LAN" {
				if ifc := strField(m, "interface"); ifc != "" {
					active = append(active, ifc)
				}
			}
		}
		if len(active) == 0 {
			report.Warnings = append(report.Warnings, "В списке интерфейсов LAN на RouterOS нет участников (добавьте bridge в Interfaces -> Interface List -> LAN).")
			return ROSSchemaCheck{Key: "lan_list", Title: "Список интерфейсов LAN пуст", OK: false, Warn: true, Detail: "нет интерфейсов в list=LAN"}
		}
		return ROSSchemaCheck{Key: "lan_list", Title: "Список интерфейсов LAN", OK: true, Detail: strings.Join(active, ", ")}
	}

	checkTableAndDefaultRoute := func() (ROSSchemaCheck, ROSSchemaCheck) {
		tblRows, err := c.rosPrint(ctx, conn, "/routing/table", []string{".id", "name", "fib", "disabled"}, "name="+tableName)
		if err != nil {
			c1 := ROSSchemaCheck{Key: "routing_table", Title: "Routing table " + tableName, OK: false, Detail: err.Error()}
			return c1, ROSSchemaCheck{Key: "default_route", Title: "Маршрут 0.0.0.0/0 -> " + conn.gatewayIP, OK: false}
		}
		hasTbl := false
		for _, r := range tblRows {
			if !isTruthyROS(r["disabled"]) && strField(r, "name") == tableName {
				hasTbl = true
				break
			}
		}
		tblCheck := ROSSchemaCheck{Key: "routing_table", Title: "Routing table " + tableName, OK: hasTbl}
		if !hasTbl {
			tblCheck.Detail = "таблица не найдена"
		} else {
			tblCheck.Detail = "OK"
		}

		rtRows, err := c.rosPrint(ctx, conn, "/ip/route", []string{".id", "dst-address", "gateway", "routing-table", "blackhole", "disabled", "comment"}, "routing-table="+tableName)
		if err != nil {
			return tblCheck, ROSSchemaCheck{Key: "default_route", Title: "Маршрут -> " + conn.gatewayIP, OK: false, Detail: err.Error()}
		}
		hasGW := false
		wrongGW := ""
		for _, r := range rtRows {
			if isTruthyROS(r["disabled"]) || isTruthyROS(r["blackhole"]) {
				continue
			}
			if strField(r, "routing-table") != tableName || strField(r, "dst-address") != "0.0.0.0/0" {
				continue
			}
			gw := stripIfaceScope(strField(r, "gateway"))
			if gw == conn.gatewayIP {
				hasGW = true
				break
			}
			if gw != "" {
				wrongGW = gw
			}
		}
		rtCheck := ROSSchemaCheck{Key: "default_route", Title: fmt.Sprintf("Маршрут в таблице %s -> %s", tableName, conn.gatewayIP), OK: hasGW}
		if hasGW {
			rtCheck.Detail = "0.0.0.0/0 via " + conn.gatewayIP
		} else if wrongGW != "" {
			rtCheck.Detail = fmt.Sprintf("найден gateway=%s вместо %s", wrongGW, conn.gatewayIP)
		} else {
			rtCheck.Detail = "default-маршрут в таблице отсутствует"
		}
		return tblCheck, rtCheck
	}

	switch mode {
	case ROSModeAddressList, ROSModeGateway:
		report.Checks = append(report.Checks, checkLANMembers())
		tblCheck, rtCheck := checkTableAndDefaultRoute()
		report.Checks = append(report.Checks, tblCheck, rtCheck, checkFasttrack())

		mangleRows, err := c.rosPrint(ctx, conn, "/ip/firewall/mangle", []string{
			".id", "chain", "action", "src-address", "in-interface", "in-interface-list",
			"dst-address-list", "connection-mark", "new-connection-mark",
			"new-routing-mark", "disabled", "comment",
		})
		if err != nil {
			report.Checks = append(report.Checks, ROSSchemaCheck{Key: "mangle", Title: "Mangle правила", OK: false, Detail: err.Error()})
		} else {
			loopGuardIdx := -1
			loopGuardViaIface := false
			markIdx := -1
			firstMarkOrRouteIdx := -1
			routeConnOK := false
			routeNewOK := false
			gwMarkAllOK := false
			for i, r := range mangleRows {
				if isTruthyROS(r["disabled"]) || strField(r, "chain") != "prerouting" {
					continue
				}
				act := strField(r, "action")
				cmt := strField(r, "comment")
				if ok, viaIface := isContainerLoopGuardRule(r, conn.gatewayIP); ok {
					if loopGuardIdx == -1 {
						loopGuardIdx = i
						loopGuardViaIface = viaIface
					} else if !viaIface {
						loopGuardViaIface = false
					}
				}
				if act == "mark-connection" && mode == ROSModeAddressList && strField(r, "dst-address-list") == listName && strField(r, "new-connection-mark") != "" {
					if markIdx == -1 {
						markIdx = i
					}
				}
				if act == "mark-connection" && mode == ROSModeGateway && cmt == "AWG_GW_Mark_All" && strField(r, "new-connection-mark") != "" {
					gwMarkAllOK = true
					if markIdx == -1 {
						markIdx = i
					}
				}
				if isMarkOrRouteRuleForTable(r, mode, listName, tableName) && firstMarkOrRouteIdx == -1 {
					firstMarkOrRouteIdx = i
				}
				if act == "mark-routing" && strField(r, "new-routing-mark") == tableName {
					if cmt == "AWG_Route_Conn" || strField(r, "connection-mark") == tableName {
						if !routeConnOK {
							routeConnOK = true
						} else {
							routeNewOK = true
						}
					}
				}
			}

			lgOK := loopGuardIdx >= 0 && (firstMarkOrRouteIdx == -1 || loopGuardIdx < firstMarkOrRouteIdx)
			lgDetail := "src-address=" + conn.gatewayIP
			if loopGuardIdx == -1 {
				lgDetail = fmt.Sprintf("нет accept для src-address=%s перед mark-правилами", conn.gatewayIP)
			} else if firstMarkOrRouteIdx >= 0 && loopGuardIdx > firstMarkOrRouteIdx {
				lgDetail = "loop-guard находится ПОСЛЕ mark-connection / mark-routing (нужно поднять выше)"
			} else if loopGuardViaIface {
				lgDetail = "in-interface / InAccept"
			}
			report.Checks = append(report.Checks, ROSSchemaCheck{
				Key:    "mangle_loop_guard",
				Title:  "Защита от петли трафика контейнера",
				OK:     lgOK,
				Detail: lgDetail,
			})

			if mode == ROSModeAddressList {
				markOK := markIdx >= 0 && routeConnOK && routeNewOK
				detail := fmt.Sprintf("address-list=%s -> table=%s", listName, tableName)
				if markIdx < 0 {
					detail = fmt.Sprintf("нет mark-connection для dst-address-list=%s", listName)
				} else if !routeConnOK || !routeNewOK {
					detail = "не хватает mark-routing правил AWG_Route_Conn / AWG_Route_New"
				}
				report.Checks = append(report.Checks, ROSSchemaCheck{
					Key:    "mangle_addrlist",
					Title:  "Mangle адрес-листа -> " + tableName,
					OK:     markOK,
					Detail: detail,
				})
			} else {
				gwOK := gwMarkAllOK && routeConnOK && routeNewOK
				detail := fmt.Sprintf("весь LAN трафик -> table=%s", tableName)
				if !gwOK {
					detail = "правила перехвата LAN -> контейнер не развёрнуты (либо используется стандартная настройка DNS/route)"
				}
				report.Checks = append(report.Checks, ROSSchemaCheck{
					Key:    "mangle_gateway",
					Title:  "Mangle шлюза (весь трафик LAN -> " + tableName + ")",
					OK:     gwOK,
					Detail: detail,
				})
			}
		}

		if mode == ROSModeAddressList {
			ctx2, cancel2 := context.WithTimeout(context.Background(), 6*time.Second)
			rows, _, alErr := c.listAddressList(ctx2, conn, c.binSync, listName)
			cancel2()
			alCheck := ROSSchemaCheck{Key: "address_list", Title: "Address-list " + listName, OK: alErr == nil}
			if alErr != nil {
				alCheck.Detail = alErr.Error()
			} else {
				managed := 0
				for _, r := range rows {
					if isManagedROSComment(r.Comment) {
						managed++
					}
				}
				alCheck.Detail = fmt.Sprintf("всего записей: %d (управляемых awg-ctl: %d)", len(rows), managed)
			}
			report.Checks = append(report.Checks, alCheck)
		}

	case ROSModeBGP:
		if tableName != "main" {
			tblRows, err := c.rosPrint(ctx, conn, "/routing/table", []string{".id", "name", "disabled"}, "name="+tableName)
			hasTbl := err == nil
			if hasTbl {
				hasTbl = false
				for _, r := range tblRows {
					if !isTruthyROS(r["disabled"]) && strField(r, "name") == tableName {
						hasTbl = true
						break
					}
				}
			}
			report.Checks = append(report.Checks, ROSSchemaCheck{
				Key:    "bgp_table",
				Title:  "Routing table " + tableName,
				OK:     hasTbl,
				Detail: map[bool]string{true: "OK", false: "таблица не найдена"}[hasTbl],
			})
		}

		filterRows, fErr := c.rosPrint(ctx, conn, "/routing/filter/rule", []string{".id", "chain", "rule", "disabled", "comment"})
		hasFilter := false
		if fErr == nil {
			for _, r := range filterRows {
				if !isTruthyROS(r["disabled"]) && strField(r, "chain") == "awg-bgp-in" {
					hasFilter = true
					break
				}
			}
		}
		fCheck := ROSSchemaCheck{Key: "bgp_filter", Title: "BGP input filter (awg-bgp-in)", OK: hasFilter}
		if fErr != nil {
			fCheck.Detail = fErr.Error()
		} else if !hasFilter {
			fCheck.Detail = "нет разрешающего фильтра (RFC 8212: RouterOS v7 отклонит eBGP-маршруты без input.filter)"
		} else {
			fCheck.Detail = "chain=awg-bgp-in active"
		}
		report.Checks = append(report.Checks, fCheck)

		bgpRows, bErr := c.rosPrint(ctx, conn, "/routing/bgp/connection", []string{
			".id", "name", "as", "remote.address", "remote.as", "local.role",
			"connect", "listen", "routing-table", "input.filter", "disabled", "comment",
		})
		connOK := false
		connDetail := "BGP peer awg-ctl-bgp не найден"
		if bErr != nil {
			connDetail = bErr.Error()
		} else {
			wantLocalAS := strconv.FormatUint(uint64(normS.ROSBGPLocalAS), 10)
			wantRemoteAS := strconv.FormatUint(uint64(normS.ROSBGPRemoteAS), 10)
			for _, r := range bgpRows {
				remAddr := strField(r, "remote.address")
				name := strField(r, "name")
				if name != "awg-ctl-bgp" && !rosAddrMatchPrefixOrIP(remAddr, conn.gatewayIP) {
					continue
				}
				if isTruthyROS(r["disabled"]) {
					connDetail = fmt.Sprintf("%s отключён", name)
					continue
				}
				if !rosAddrMatchPrefixOrIP(remAddr, conn.gatewayIP) {
					connDetail = fmt.Sprintf("%s: remote.address=%s (нужно %s/32)", name, remAddr, conn.gatewayIP)
					continue
				}
				if strField(r, "as") != wantRemoteAS || strField(r, "remote.as") != wantLocalAS {
					connDetail = fmt.Sprintf("%s: AS=%s/remote.as=%s (ожидалось %s/%s)",
						name, strField(r, "as"), strField(r, "remote.as"), wantRemoteAS, wantLocalAS)
					continue
				}
				if !isTruthyROS(r["listen"]) {
					connDetail = fmt.Sprintf("%s: требуется listen=yes", name)
					continue
				}
				if strField(r, "input.filter") == "" {
					connDetail = fmt.Sprintf("%s: не задан input.filter", name)
					continue
				}
				connOK = true
				connDetail = fmt.Sprintf("%s (AS%s <- AS%s, peer=%s, table=%s)", name, wantRemoteAS, wantLocalAS, remAddr, firstNonEmpty(strField(r, "routing-table"), "main"))
				break
			}
		}
		report.Checks = append(report.Checks, ROSSchemaCheck{
			Key:    "bgp_conn",
			Title:  "BGP peer на RouterOS",
			OK:     connOK,
			Detail: connDetail,
		})

		bgpSt := c.bgpSpeaker.Status()
		report.Checks = append(report.Checks, ROSSchemaCheck{
			Key:    "bgp_session",
			Title:  "Сессия BGP в контейнере",
			OK:     bgpSt.State == "established",
			Detail: fmt.Sprintf("state=%s, routes=%d, peer=%s %s", bgpSt.State, bgpSt.AnnouncedRoutes, bgpSt.Peer, bgpSt.LastError),
		})

	default: // manual
		if tableName != "main" && tableName != "" {
			tblRows, err := c.rosPrint(ctx, conn, "/routing/table", []string{".id", "name", "disabled"}, "name="+tableName)
			hasTbl := err == nil && len(tblRows) > 0
			report.Checks = append(report.Checks, ROSSchemaCheck{
				Key:    "routing_table",
				Title:  "Routing table " + tableName,
				OK:     hasTbl,
				Detail: map[bool]string{true: "OK", false: "не найдена"}[hasTbl],
			})
		}
		dnsRaw, _, dnsErr := c.doWithConn(conn, http.MethodGet, "/ip/dns", nil)
		allowRemote := false
		dnsDetail := ""
		if dnsErr == nil {
			var obj map[string]any
			if json.Unmarshal(dnsRaw, &obj) == nil {
				allowRemote = isTruthyROS(obj["allow-remote-requests"])
				dnsDetail = fmt.Sprintf("allow-remote-requests=%v", allowRemote)
			}
		} else {
			dnsDetail = dnsErr.Error()
		}
		report.Checks = append(report.Checks, ROSSchemaCheck{
			Key:    "dns_remote",
			Title:  "DNS allow-remote-requests",
			OK:     allowRemote,
			Warn:   !allowRemote,
			Detail: dnsDetail,
		})
	}

	if mode == ROSModeAddressList || mode == ROSModeBGP {
		c.appendIPDNSRoutingWarnings(ctx, conn, listName, &report)
	}
	c.appendIPServiceSecurityWarnings(ctx, conn, &report)

	allOK := len(report.Checks) > 0
	for _, ch := range report.Checks {
		if !ch.OK && !ch.Warn {
			allOK = false
			break
		}
		if !ch.OK && ch.Warn {
			// Warn checks like empty LAN list or missing fasttrack keep report non-OK so user sees action needed
			allOK = false
			break
		}
	}
	report.OK = allOK
	return report
}

// ProvisionSchema explicitly and idempotently applies the required RouterOS objects
// for the configured ros_mode upon explicit user action.
func (c *ROSClient) ProvisionSchema(s AppSettings, opts ROSProvisionOptions) ROSProvisionResult {
	conn, normS, mode, listName, tableName := c.snapshotSettingsForSchema(s, &opts)
	res := ROSProvisionResult{}

	if conn.baseURL == "" && !(conn.useBinAPI && conn.binCfg.Addr != "") {
		res.Error = "RouterOS не настроен"
		res.Report = c.InspectSchema(normS)
		return res
	}
	if conn.urlErr != "" {
		res.Error = conn.urlErr
		res.Report = c.InspectSchema(normS)
		return res
	}
	if conn.user == "" {
		res.Error = "Не указан ROS_USER"
		res.Report = c.InspectSchema(normS)
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var applied []string

	ensureRoutingTable := func(name string) error {
		rows, err := c.rosPrint(ctx, conn, "/routing/table", []string{".id", "name", "fib", "disabled"}, "name="+name)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if strField(r, "name") == name {
				id := strField(r, ".id")
				if isTruthyROS(r["disabled"]) && id != "" {
					if err := c.rosSet(ctx, conn, "/routing/table", id, map[string]string{"disabled": "no", "fib": "yes"}); err != nil {
						return err
					}
					applied = append(applied, "enabled routing table "+name)
				}
				return nil
			}
		}
		if err := c.rosAdd(ctx, conn, "/routing/table", map[string]string{
			"name": name,
			"fib":  "yes",
		}); err != nil {
			return err
		}
		applied = append(applied, "created routing table "+name)
		return nil
	}

	ensureDefaultRoutes := func(tbl string) error {
		rows, err := c.rosPrint(ctx, conn, "/ip/route", []string{".id", "dst-address", "gateway", "routing-table", "blackhole", "disabled", "comment"}, "routing-table="+tbl)
		if err != nil {
			return err
		}
		var foundDefID, foundBHID string
		var foundDefGW, foundDefTbl string
		var foundDefDisabled, foundBHDisabled bool
		for _, r := range rows {
			cmt := strField(r, "comment")
			dst := strField(r, "dst-address")
			rtbl := strField(r, "routing-table")
			id := strField(r, ".id")
			if cmt == "AmneziaWGRoS_default" || (dst == "0.0.0.0/0" && rtbl == tbl && !isTruthyROS(r["blackhole"])) {
				if foundDefID == "" {
					foundDefID = id
					foundDefGW = stripIfaceScope(strField(r, "gateway"))
					foundDefTbl = rtbl
					foundDefDisabled = isTruthyROS(r["disabled"])
				}
			}
			if cmt == "AmneziaWGRoS_bh" || (dst == "0.0.0.0/0" && rtbl == tbl && isTruthyROS(r["blackhole"])) {
				if foundBHID == "" {
					foundBHID = id
					foundBHDisabled = isTruthyROS(r["disabled"])
				}
			}
		}

		if foundDefID == "" {
			if err := c.rosAdd(ctx, conn, "/ip/route", map[string]string{
				"dst-address":   "0.0.0.0/0",
				"gateway":       conn.gatewayIP,
				"routing-table": tbl,
				"comment":       "AmneziaWGRoS_default",
			}); err != nil {
				return err
			}
			applied = append(applied, fmt.Sprintf("added route 0.0.0.0/0 -> %s (table=%s)", conn.gatewayIP, tbl))
		} else if foundDefGW != conn.gatewayIP || foundDefTbl != tbl || foundDefDisabled {
			if err := c.rosSet(ctx, conn, "/ip/route", foundDefID, map[string]string{
				"gateway":       conn.gatewayIP,
				"routing-table": tbl,
				"disabled":      "no",
				"comment":       "AmneziaWGRoS_default",
			}); err != nil {
				return err
			}
			applied = append(applied, fmt.Sprintf("updated route 0.0.0.0/0 -> %s (table=%s)", conn.gatewayIP, tbl))
		}

		if foundBHID == "" {
			if err := c.rosAdd(ctx, conn, "/ip/route", map[string]string{
				"dst-address":   "0.0.0.0/0",
				"blackhole":     "yes",
				"distance":      "254",
				"routing-table": tbl,
				"comment":       "AmneziaWGRoS_bh",
			}); err != nil {
				return err
			}
			applied = append(applied, "added blackhole fallback route in "+tbl)
		} else if foundBHDisabled {
			_ = c.rosSet(ctx, conn, "/ip/route", foundBHID, map[string]string{"disabled": "no"})
		}
		return nil
	}

	ensureFasttrackNoMark := func() error {
		rows, err := c.rosPrint(ctx, conn, "/ip/firewall/filter", []string{".id", "action", "connection-mark", "disabled"})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if isTruthyROS(r["disabled"]) || strField(r, "action") != "fasttrack-connection" {
				continue
			}
			if strings.TrimSpace(strField(r, "connection-mark")) == "" {
				id := strField(r, ".id")
				if id != "" {
					if err := c.rosSet(ctx, conn, "/ip/firewall/filter", id, map[string]string{"connection-mark": "no-mark"}); err != nil {
						return err
					}
					applied = append(applied, "updated fasttrack rule "+id+" -> connection-mark=no-mark")
				}
			}
		}
		return nil
	}

	ensureInterfaceList := func(name string) error {
		rows, err := c.rosPrint(ctx, conn, "/interface/list", []string{".id", "name"}, "name="+name)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if strField(r, "name") == name {
				return nil
			}
		}
		if err := c.rosAdd(ctx, conn, "/interface/list", map[string]string{"name": name}); err != nil {
			return err
		}
		applied = append(applied, "created interface list "+name)
		return nil
	}

	upsertMangleRule := func(existing []map[string]any, matchComment string, fields map[string]string, placeBeforeID string) (string, error) {
		for _, r := range existing {
			if strField(r, "comment") != matchComment {
				continue
			}
			id := strField(r, ".id")
			needsUpdate := isTruthyROS(r["disabled"])
			if !needsUpdate {
				for k, v := range fields {
					if strField(r, k) != v {
						needsUpdate = true
						break
					}
				}
			}
			if needsUpdate && id != "" {
				setFields := make(map[string]string, len(fields)+1)
				for k, v := range fields {
					setFields[k] = v
				}
				setFields["disabled"] = "no"
				if err := c.rosSet(ctx, conn, "/ip/firewall/mangle", id, setFields); err != nil {
					return id, err
				}
				applied = append(applied, "updated mangle "+matchComment)
			}
			return id, nil
		}

		addFields := make(map[string]string, len(fields)+2)
		for k, v := range fields {
			addFields[k] = v
		}
		addFields["comment"] = matchComment
		if placeBeforeID != "" {
			addFields["place-before"] = placeBeforeID
		}
		if err := c.rosAdd(ctx, conn, "/ip/firewall/mangle", addFields); err != nil {
			// Fallback without place-before if API rejects relative ID placement
			if placeBeforeID != "" {
				delete(addFields, "place-before")
				if err2 := c.rosAdd(ctx, conn, "/ip/firewall/mangle", addFields); err2 == nil {
					applied = append(applied, "added mangle "+matchComment)
					return "", nil
				}
			}
			return "", err
		}
		applied = append(applied, "added mangle "+matchComment)
		return "", nil
	}

	var provErr error
	switch mode {
	case ROSModeAddressList, ROSModeGateway:
		if err := ensureInterfaceList("LAN"); err != nil {
			provErr = err
			break
		}
		if err := ensureRoutingTable(tableName); err != nil {
			provErr = err
			break
		}
		if err := ensureDefaultRoutes(tableName); err != nil {
			provErr = err
			break
		}
		if err := ensureFasttrackNoMark(); err != nil {
			provErr = err
			break
		}
		mangles, err := c.rosPrint(ctx, conn, "/ip/firewall/mangle", []string{
			".id", "chain", "action", "src-address", "dst-address", "in-interface", "in-interface-list",
			"dst-address-type", "dst-address-list", "connection-mark", "connection-state",
			"new-connection-mark", "new-routing-mark", "passthrough", "disabled", "comment",
		})
		if err != nil {
			provErr = err
			break
		}

		var markAnchorID string
		markAnchorIdx := -1
		containerIdx := -1
		for i, r := range mangles {
			cmt := strField(r, "comment")
			if cmt == "AWG_Accept_Container" && containerIdx == -1 {
				containerIdx = i
			}
			if strField(r, "chain") == "prerouting" && isMarkOrRouteRuleForTable(r, mode, listName, tableName) {
				if markAnchorID == "" {
					markAnchorID = strField(r, ".id")
					markAnchorIdx = i
				}
			}
		}

		// Always place container loop-guard before any mark-connection or mark-routing rule.
		containerRuleID, err := upsertMangleRule(mangles, "AWG_Accept_Container", map[string]string{
			"chain":       "prerouting",
			"action":      "accept",
			"src-address": conn.gatewayIP,
		}, markAnchorID)
		if err != nil {
			provErr = err
			break
		}
		if containerRuleID != "" && markAnchorID != "" && markAnchorIdx >= 0 && containerIdx > markAnchorIdx {
			if mErr := c.rosMoveBefore(ctx, conn, "/ip/firewall/mangle", containerRuleID, markAnchorID); mErr == nil {
				applied = append(applied, "moved AWG_Accept_Container before mark rule")
			}
		}
		if _, err := upsertMangleRule(mangles, "AWG_Accept_no_mark", map[string]string{
			"chain":            "prerouting",
			"action":           "accept",
			"connection-mark":  "no-mark",
			"connection-state": "established",
		}, markAnchorID); err != nil {
			provErr = err
			break
		}

		if mode == ROSModeGateway {
			for _, bp := range []struct {
				cmt  string
				cidr string
			}{
				{"AWG_GW_Bypass_10", "10.0.0.0/8"},
				{"AWG_GW_Bypass_172", "172.16.0.0/12"},
				{"AWG_GW_Bypass_192", "192.168.0.0/16"},
			} {
				if _, err := upsertMangleRule(mangles, bp.cmt, map[string]string{
					"chain":             "prerouting",
					"action":            "accept",
					"in-interface-list": "LAN",
					"dst-address":       bp.cidr,
				}, markAnchorID); err != nil {
					provErr = err
					break
				}
			}
			if provErr != nil {
				break
			}
		}

		if _, err := upsertMangleRule(mangles, "AWG_Route_Conn", map[string]string{
			"chain":             "prerouting",
			"action":            "mark-routing",
			"in-interface-list": "LAN",
			"connection-mark":   tableName,
			"new-routing-mark":  tableName,
			"passthrough":       "no",
		}, ""); err != nil {
			provErr = err
			break
		}

		if mode == ROSModeAddressList {
			if _, err := upsertMangleRule(mangles, "AWG_Mark_AddressList", map[string]string{
				"chain":               "prerouting",
				"action":              "mark-connection",
				"in-interface-list":   "LAN",
				"connection-mark":     "no-mark",
				"connection-state":    "new",
				"dst-address-type":    "!local",
				"dst-address-list":    listName,
				"new-connection-mark": tableName,
			}, ""); err != nil {
				provErr = err
				break
			}
		} else {
			if _, err := upsertMangleRule(mangles, "AWG_GW_Mark_All", map[string]string{
				"chain":               "prerouting",
				"action":              "mark-connection",
				"in-interface-list":   "LAN",
				"connection-mark":     "no-mark",
				"connection-state":    "new",
				"dst-address-type":    "!local",
				"new-connection-mark": tableName,
			}, ""); err != nil {
				provErr = err
				break
			}
		}

		if _, err := upsertMangleRule(mangles, "AWG_Route_New", map[string]string{
			"chain":             "prerouting",
			"action":            "mark-routing",
			"in-interface-list": "LAN",
			"connection-mark":   tableName,
			"new-routing-mark":  tableName,
			"passthrough":       "no",
		}, ""); err != nil {
			provErr = err
			break
		}

	case ROSModeBGP:
		if tableName != "" && tableName != "main" {
			if err := ensureRoutingTable(tableName); err != nil {
				provErr = err
				break
			}
		}
		filterRows, err := c.rosPrint(ctx, conn, "/routing/filter/rule", []string{".id", "chain", "rule", "disabled", "comment"})
		if err != nil {
			provErr = err
			break
		}
		wantRule := "if (dst in 0.0.0.0/0 && dst-len > 0) { accept }"
		var filterID string
		var filterNeedsSet bool
		for _, r := range filterRows {
			if strField(r, "chain") == "awg-bgp-in" && (strField(r, "comment") == "awg-ctl:bgp-in" || strField(r, "rule") != "") {
				filterID = strField(r, ".id")
				if isTruthyROS(r["disabled"]) || strField(r, "rule") != wantRule {
					filterNeedsSet = true
				}
				break
			}
		}
		if filterID == "" {
			if err := c.rosAdd(ctx, conn, "/routing/filter/rule", map[string]string{
				"chain":   "awg-bgp-in",
				"rule":    wantRule,
				"comment": "awg-ctl:bgp-in",
			}); err != nil {
				provErr = err
				break
			}
			applied = append(applied, "added BGP input filter rule awg-bgp-in")
		} else if filterNeedsSet {
			if err := c.rosSet(ctx, conn, "/routing/filter/rule", filterID, map[string]string{
				"rule":     wantRule,
				"disabled": "no",
				"comment":  "awg-ctl:bgp-in",
			}); err != nil {
				provErr = err
				break
			}
			applied = append(applied, "updated BGP input filter rule awg-bgp-in")
		}

		role := "ebgp"
		if normS.ROSBGPLocalAS == normS.ROSBGPRemoteAS {
			role = "ibgp"
		}
		bgpFields := map[string]string{
			"name":             "awg-ctl-bgp",
			"as":               strconv.FormatUint(uint64(normS.ROSBGPRemoteAS), 10),
			"remote.address":   conn.gatewayIP + "/32",
			"remote.as":        strconv.FormatUint(uint64(normS.ROSBGPLocalAS), 10),
			"local.role":     role,
			"connect":        "no",
			"listen":         "yes",
			"routing-table":  tableName,
			"input.filter":     "awg-bgp-in",
			"comment":          "awg-ctl:bgp",
		}
		bgpRows, err := c.rosPrint(ctx, conn, "/routing/bgp/connection", []string{
			".id", "name", "as", "remote.address", "remote.as", "local.role",
			"connect", "listen", "routing-table", "input.filter", "disabled", "comment",
		})
		if err != nil {
			provErr = err
			break
		}
		var bgpID string
		for _, r := range bgpRows {
			if strField(r, "name") == "awg-ctl-bgp" || strField(r, "comment") == "awg-ctl:bgp" {
				bgpID = strField(r, ".id")
				break
			}
		}
		if bgpID == "" {
			if err := c.rosAdd(ctx, conn, "/routing/bgp/connection", bgpFields); err != nil {
				provErr = err
				break
			}
			applied = append(applied, fmt.Sprintf("added BGP peer awg-ctl-bgp (%s/32 AS%d)", conn.gatewayIP, normS.ROSBGPLocalAS))
		} else {
			bgpFields["disabled"] = "no"
			if err := c.rosSet(ctx, conn, "/routing/bgp/connection", bgpID, bgpFields); err != nil {
				provErr = err
				break
			}
			applied = append(applied, fmt.Sprintf("updated BGP peer awg-ctl-bgp (%s/32 AS%d)", conn.gatewayIP, normS.ROSBGPLocalAS))
		}

	default: // manual
		if tableName != "" && tableName != "main" {
			if err := ensureRoutingTable(tableName); err != nil {
				provErr = err
				break
			}
		}
	}

	if provErr == nil && opts.SetupDNS {
		if err := c.rosSet(ctx, conn, "/ip/dns", "", map[string]string{
			"allow-remote-requests": "yes",
			"servers":               conn.gatewayIP,
		}); err != nil {
			provErr = err
		} else {
			applied = append(applied, "configured /ip/dns servers="+conn.gatewayIP)
		}
	}

	res.Applied = applied
	res.Report = c.InspectSchema(normS)
	if provErr != nil {
		res.Error = provErr.Error()
		res.OK = false
		return res
	}
	res.OK = true
	if c.logger != nil && len(applied) > 0 {
		c.logger.Logf("ROS schema provisioned (%s): %s", mode, strings.Join(applied, "; "))
	}
	return res
}

func (c *ROSClient) readIPDNSConfig(ctx context.Context, conn rosConnConfig) (map[string]any, error) {
	if binCfg, ok := canUseBinAPI(conn); ok && c.binSync != nil {
		rows, err := c.binSync.Exec(ctx, binCfg, "/ip/dns/print", "=.proplist=servers,dynamic-servers,allow-remote-requests")
		if err == nil && len(rows) > 0 {
			out := make(map[string]any, len(rows[0]))
			for k, v := range rows[0] {
				out[k] = v
			}
			return out, nil
		}
		if !isBinTransportFallbackErr(err) || conn.baseURL == "" {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("empty /ip/dns response")
		}
	}
	if conn.baseURL == "" {
		return nil, errors.New("RouterOS REST URL is not configured")
	}
	raw, _, err := c.doWithConn(conn, http.MethodGet, "/ip/dns", nil)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil && obj != nil {
		return obj, nil
	}
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return arr[0], nil
	}
	return nil, errors.New("unexpected /ip/dns JSON shape")
}

func (c *ROSClient) appendIPDNSRoutingWarnings(ctx context.Context, conn rosConnConfig, listName string, report *ROSSchemaReport) {
	if report == nil || conn.gatewayIP == "" {
		return
	}
	obj, err := c.readIPDNSConfig(ctx, conn)
	if err != nil || obj == nil {
		return
	}
	parseCSV := func(raw string) []string {
		var out []string
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	staticServers := parseCSV(strField(obj, "servers"))
	dynamicServers := parseCSV(strField(obj, "dynamic-servers"))

	hasContainer := false
	hasExtraStatic := false
	for _, s := range staticServers {
		if s == conn.gatewayIP {
			hasContainer = true
		} else {
			hasExtraStatic = true
		}
	}

	if !hasContainer {
		shown := strField(obj, "servers")
		if shown == "" && len(dynamicServers) > 0 {
			shown = "dynamic: " + strings.Join(dynamicServers, ",")
		}
		if shown == "" {
			shown = "не задан"
		}
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"RouterOS /ip/dns (%s) не указывает на DNS контейнера %s: динамические правила geosite:/domain: не будут наполнять %s автоматически через клиентские DNS-запросы.",
			shown, conn.gatewayIP, listName))
		return
	}
	if hasExtraStatic || len(dynamicServers) > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"В RouterOS /ip/dns кроме контейнера %s есть дополнительные DNS (%s%s) — часть запросов geosite:/domain: может идти мимо awg-ctl.",
			conn.gatewayIP, strings.Join(staticServers, ","), func() string {
				if len(dynamicServers) > 0 {
					return " + dynamic:" + strings.Join(dynamicServers, ",")
				}
				return ""
			}()))
	}
}

func (c *ROSClient) appendIPServiceSecurityWarnings(ctx context.Context, conn rosConnConfig, report *ROSSchemaReport) {
	if report == nil {
		return
	}
	rows, err := c.rosPrint(ctx, conn, "/ip/service", []string{".id", "name", "port", "address", "certificate", "disabled"})
	if err != nil || len(rows) == 0 {
		return
	}
	for _, r := range rows {
		if isTruthyROS(r["disabled"]) {
			continue
		}
		name := strings.ToLower(strField(r, "name"))
		addr := strings.TrimSpace(strField(r, "address"))
		cert := strings.TrimSpace(strField(r, "certificate"))
		switch name {
		case "api", "www", "api-ssl", "www-ssl":
			if addr == "" {
				report.Warnings = append(report.Warnings, fmt.Sprintf(
					"Безопасность RouterOS: сервис /ip/service %s (port=%s) открыт с любых IP (address=\"\"). Рекомендуется ограничить address= подсетью контейнера и LAN.",
					name, strField(r, "port")))
			}
			if name == "api-ssl" && (cert == "" || strings.EqualFold(cert, "none")) {
				report.Warnings = append(report.Warnings,
					"RouterOS /ip/service api-ssl включён без сертификата (certificate=none): TLS API-клиенты не смогут подключиться, пока не выбран сертификат.")
			}
		}
	}
}
