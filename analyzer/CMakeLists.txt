spicy_add_analyzer(
    NAME NJRAT
    PACKAGE_NAME zeek-njrat-detector
    SOURCES njrat.spicy njrat.evt zeek_njrat.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
