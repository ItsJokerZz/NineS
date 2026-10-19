#include "nineS.hpp"
#include "remote.hpp"

#include <cerrno>
#include <cstdarg>
#include <cstdio>

static void (*sink)(const char *line);

void set_logger(void (*logger)(const char *line)) { sink = logger; }

void log_line(const char *format, ...) {
  if (!sink)
    return;

  int saved = errno;
  char line[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(line, sizeof(line), format, args);
  va_end(args);

  sink(line);
  errno = saved;
}
