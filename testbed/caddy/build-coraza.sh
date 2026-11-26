#!/bin/sh
set -eu
module=github.com/corazawaf/coraza-caddy/v2
version=v2.6.2
go mod download "$module@$version"
cp -R "$(go env GOMODCACHE)/$module@$version" /tmp/coraza-caddy
chmod u+w /tmp/coraza-caddy/coraza.go
file=/tmp/coraza-caddy/coraza.go
# Keep request values out of both the match callback and the interruption log.
sed -i '/config := coraza.NewWAFConfig()/,+2c\
	config := coraza.NewWAFConfig()
/zap.String("uri", r.RequestURI),/d
/"net\/http"/a\
	"strconv"\
	"slices"
/tx.ProcessLogging()/a\
		m.logRuleIDs(r, tx)
' "$file"
cat >> "$file" <<'GO'

func (m corazaModule) logRuleIDs(r *http.Request, tx types.Transaction) {
	rules := make([]int, 0)
	seen := make(map[int]bool)
	score := 0
	for _, match := range tx.MatchedRules() {
		rule := match.Rule()
		id := rule.ID()
		if id == 100100 {
			for _, data := range match.MatchedDatas() {
				score, _ = strconv.Atoi(data.Value())
			}
		}
		isAttack := slices.Contains(rule.Tags(), "attack-xss") || slices.Contains(rule.Tags(), "attack-sqli")
		if id >= 941000 && id < 943000 && isAttack && !seen[id] {
			rules = append(rules, id)
			seen[id] = true
		}
	}
	if len(rules) == 0 {
		return
	}
	client, _ := getClientAddress(r)
	m.logger.Named("matches").Info("CRS match",
		zap.String("request_id", tx.ID()),
		zap.String("client_ip", client),
		zap.Ints("rule_ids", rules),
		zap.Int("score", score),
		zap.Bool("blocked", tx.Interruption() != nil),
	)
}
GO
xcaddy build v2.11.9 --output /usr/bin/caddy --with "$module=/tmp/coraza-caddy"
