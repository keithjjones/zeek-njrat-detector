signature dpd_njrat {
    ip-proto == tcp
    payload /^[0-9]+\x00[a-zA-Z]+\|/
#    requires-reverse-signature dpd_njrat_client
    enable "spicy_NJRAT"
}