package main

import "testing"

func TestParseURLDoubleColon(t *testing.T) {
	url := "ant://dGVzdGtleQ==@192.168.1.100::8443?obfs=tls"
	pk, host, tm, _, err := ParseURL(url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk != "dGVzdGtleQ==" {
		t.Fatalf("expected key dGVzdGtleQ==, got %s", pk)
	}
	if host != "192.168.1.100:8443" {
		t.Fatalf("expected host 192.168.1.100:8443, got %s", host)
	}
	if tm != "tls" {
		t.Fatalf("expected transport tls, got %s", tm)
	}
}

func TestParseURLNoPort(t *testing.T) {
	url := "ant://dGVzdGtleQ==@my.server.com?obfs=tls"
	_, host, _, _, err := ParseURL(url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "my.server.com:8443" {
		t.Fatalf("expected host my.server.com:8443, got %s", host)
	}
}
