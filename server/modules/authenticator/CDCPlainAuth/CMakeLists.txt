add_library(cdcplainauth SHARED cdc_plain_auth.cc)
target_link_libraries(cdcplainauth maxscale-common)
set_target_properties(cdcplainauth PROPERTIES VERSION "1.0.0" LINK_FLAGS -Wl,-z,defs)
install_module(cdcplainauth core)
