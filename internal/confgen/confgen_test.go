package confgen

import (
	"strings"
	"testing"

	"github.com/gexqin/wgmgt/internal/store"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestInterfaceFull(t *testing.T) {
	ifc := &store.Interface{
		Name: "wg0", PrivateKey: "PRIV", Address: "10.0.0.1/24",
		ListenPort: 51820, MTU: 1420, DNS: "10.0.0.1",
	}
	peers := []store.Peer{
		{Name: "laptop", PublicKey: "PUB1", AllowedIPs: "10.0.0.2/32", Endpoint: "1.2.3.4:51820", Keepalive: 25},
		{Name: "phone", PublicKey: "PUB2", AllowedIPs: "10.0.0.3/32,192.168.7.0/24", PresharedKey: "PSK"},
	}
	out := Interface(ifc, peers)

	for _, want := range []string{
		"[Interface]\nPrivateKey = PRIV\nAddress = 10.0.0.1/24\nListenPort = 51820\nMTU = 1420\nDNS = 10.0.0.1\n",
		"[Peer]\nPublicKey = PUB1\nAllowedIPs = 10.0.0.2/32\nEndpoint = 1.2.3.4:51820\nPersistentKeepalive = 25\n",
		"[Peer]\nPublicKey = PUB2\nPresharedKey = PSK\nAllowedIPs = 10.0.0.3/32,192.168.7.0/24\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q;\ngot:\n%s", want, out)
		}
	}
}

func TestInterfaceOmitsEmptyFields(t *testing.T) {
	out := Interface(&store.Interface{PrivateKey: "PRIV", Address: "10.0.0.1/24"}, nil)
	for _, unwanted := range []string{"ListenPort", "MTU", "DNS", "Table", "FwMark", "PostUp", "[Peer]"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output should not contain %q:\n%s", unwanted, out)
		}
	}
}

func TestClientDerivesServerKeyAndTunnelNet(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ifc := &store.Interface{PrivateKey: priv.String(), Address: "10.10.0.1/24"}
	p := &store.Peer{
		ClientPrivateKey: "CLIENTPRIV", PublicKey: "PUB",
		AllowedIPs: "10.10.0.7/32", Keepalive: 25,
	}
	out, err := Client(ifc, p, "vpn.example.com:51820")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PrivateKey = CLIENTPRIV\n",
		"Address = 10.10.0.7/32\n",
		"PublicKey = " + priv.PublicKey().String() + "\n",
		"Endpoint = vpn.example.com:51820\n",
		"AllowedIPs = 10.10.0.0/24\n",
		"PersistentKeepalive = 25\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q;\ngot:\n%s", want, out)
		}
	}
}

func TestClientFirstAllowedIPAsAddress(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ifc := &store.Interface{PrivateKey: priv.String(), Address: "10.0.0.1/24"}
	out, err := Client(ifc, &store.Peer{ClientPrivateKey: "c", AllowedIPs: "10.0.0.9/32,192.168.5.0/24"}, "e:1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Address = 10.0.0.9/32\n") {
		t.Errorf("client address should use first allowed IP:\n%s", out)
	}
}
