/* Host test interface; the real bridge.c remains in a separately licensed checkout. */
#include "bridge.h"
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif
EXPORT void test_translate(const uint8_t *in, uint8_t *out) { stadia_to_xbox360(in, out); }
EXPORT void test_parse_flags(const uint8_t *in, size_t len, uint8_t *out) {
    stadia_controller_state_t s;
    stadia_parse_state(in, len, &s);
    out[0]=s.assistant; out[1]=s.capture; out[2]=s.rs; out[3]=s.options;
    out[4]=s.menu; out[5]=s.stadia; out[6]=s.a; out[7]=s.b;
    out[8]=s.x; out[9]=s.y; out[10]=s.lb; out[11]=s.rb; out[12]=s.ls;
}
