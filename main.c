#if IN_SHELL /* $ bash main.c
 cc main.c -o hakanssn.com -fsanitize=undefined -g3 -Os -Wall -Wextra -Wconversion -Wno-sign-conversion -Wno-unused-function $@
 exit # */
#endif

#define assert(c)        while (!(c)) __builtin_unreachable()
#define tassert(c)       while (!(c)) __builtin_trap()
#define breakpoint(c)    ((c) ? ({ asm volatile ("int3; nop"); }) : 0)
#define countof(a)       (Iz)(sizeof(a) / sizeof(*(a)))
#define new(a, t, n)     ((t *)arena_alloc(a, sizeof(t), _Alignof(t), (n)))
#define newbeg(a, t, n)  ((t *)arena_alloc_beg(a, sizeof(t), _Alignof(t), (n)))
#define s8(s)            (S8){(U8 *)s, countof(s)-1}
#define memcpy(d, s, n)  __builtin_memcpy(d, s, n)
#define memset(d, c, n)  __builtin_memset(d, c, n)

typedef unsigned char U8;
typedef signed long long I64;
typedef typeof((char *)0-(char *)0) Iz;
typedef typeof(sizeof(0))           Uz;

////////////////////////////////////////////////////////////////////////////////
//- Arena

typedef struct { U8 *beg; U8 *end; } Arena;

__attribute((malloc, alloc_size(4, 2), alloc_align(3)))
static U8 *arena_alloc(Arena *a, Iz objsize, Iz align, Iz count) {
  Iz padding = (Uz)a->end & (align - 1);
  tassert((count <= (a->end - a->beg - padding) / objsize) && "out of memory");
  Iz total = objsize * count;
  return memset(a->end -= total + padding, 0, total);
}

__attribute((malloc, alloc_size(4, 2), alloc_align(3)))
static U8 *arena_alloc_beg(Arena *a, Iz objsize, Iz align, Iz count) {
  Iz padding = -(Uz)(a->beg) & (align - 1);
  Iz total   = padding + objsize * count;
  tassert(total < (a->end - a->beg) && "out of memory");
  U8 *p = a->beg + padding;
  memset(p, 0, objsize * count);
  a->beg += total;
  return p;
}

////////////////////////////////////////////////////////////////////////////////
//- String

#define s8pri(s) (int)s.len, s.data

typedef struct { U8 *data; Iz len; } S8;

static S8 s8span(U8 *beg, U8 *end) { return (S8){beg, end - beg}; }

static S8 s8dup(Arena *a, S8 s) {
  return (S8) {
    memcpy((new(a, U8, s.len)), s.data, s.len * sizeof(U8)),
    s.len,
  };
}

static char *s8z(Arena *a, S8 s) {
  return memcpy(new(a, char, s.len + 1), s.data, s.len);
}

static S8 s8cstr(Arena *a, char *cstr) {
  return s8dup(a, (S8){(U8*)cstr, __builtin_strlen(cstr)});
}

#define s8concat(arena, head, ...)                                                   \
  s8concatv(arena, head, ((S8[]){__VA_ARGS__}), (countof(((S8[]){__VA_ARGS__}))))

static S8 s8concatv(Arena *a, S8 head, S8 *ss, Iz count) {
  S8 r = {0};
  if (!head.data || (U8 *)(head.data+head.len) != a->beg) {
    S8 copy = head;
    copy.data = newbeg(a, U8, head.len);
    if (head.len) memcpy(copy.data, head.data, head.len);
    head = copy;
  }
  for (Iz i = 0; i < count; i++) {
    S8 tail = ss[i];
    U8 *data = newbeg(a, U8, tail.len);
    if (tail.len) memcpy(data, tail.data, tail.len);
    head.len += tail.len;
  }
  r = head;
  return r;
}

static S8 s8trimspace(S8 s) {
  for (Iz off = 0; off < s.len; off++) {
    _Bool is_ws = (s.data[off] == ' ' || ((unsigned)s.data[off] - '\t') < 5);
    if (!is_ws) { return (S8){s.data + off, s.len - off}; }
  }
  return s;
}

static _Bool s8match(S8 a, S8 b, Iz n) {
  if (a.len < n || b.len < n)  { return 0; }
  for (Iz i = 0; i < n; i++) {
    if (a.data[i] != b.data[i]) { return 0; }
  }
  return 1;
}

static _Bool s8equal(S8 a, S8 b) {
  if (a.len != b.len)  { return 0; }
  return s8match(a, b, a.len);
}

#define s8startswith(a, b) s8match((a), (b), (b).len)

static S8 s8tolower(S8 s) {
  for (Iz i = 0; i < s.len; i++) {
    if (((unsigned)s.data[i] - 'A') < 26) {
      s.data[i] |= 32;
    }
  }
  return s;
}

typedef struct {
  S8 head, tail;
} S8pair;

static S8pair s8cut(S8 s, U8 c) {
  S8pair r = {0};
  if (s.data) {
    U8 *beg = s.data;
    U8 *end = s.data + s.len;
    U8 *cut = beg;
    for (; cut < end && *cut != c; cut++) {}
    r.head = s8span(beg, cut);
    if (cut < end) {
      r.tail = s8span(cut + 1, end);
    }
  }
  return r;
}

static S8 s8i64(Arena *arena, I64 x) {
  _Bool negative = (x < 0);
  if (negative) { x = -x; }
  char digits[20];
  int i = countof(digits);
  do {
    digits[--i] = (char)(x % 10) + '0';
  } while (x /= 10);
  Iz len = countof(digits) - i + negative;
  U8 *beg = new(arena, U8, len);
  U8 *end = beg;
  if (negative) { *end++ = '-'; }
  do { *end++ = digits[i++]; } while (i < countof(digits));
  return (S8){beg, len};
}

////////////////////////////////////////////////////////////////////////////////
//- Error side channel

extern __thread struct ErrList *errors;

typedef struct Err Err;
struct Err {
  Err *next;
  int severity;
  S8 message;
};

typedef struct ErrList {
  Arena rewind_arena; // original [beg, end) range for rewinding
  Arena arena;
  Err *first;
  int max_severity;
} ErrList;

static ErrList *errors_make(Arena *arena, Iz nbyte) {
  assert(errors == 0);
  ErrList *r = new(arena, ErrList, 1);
  U8 *beg = new(arena, U8, nbyte);
  r->arena = r->rewind_arena = (Arena){beg, beg + nbyte};
  return r;
}

static int errors_get_max_severity_and_reset() {
  int max_severity = errors->max_severity;
  errors->first = 0;
  errors->max_severity = 0;
  errors->arena = errors->rewind_arena;
  return max_severity;
}

#define for_errors(varname)                                                    \
  for (Iz _defer_i_ = 1; _defer_i_; _defer_i_--)                               \
    for (Err *varname = errors->first; varname && (errors->max_severity > 0);  \
         varname = varname->next)

static Err *emit_err(int severity, S8 message) {
  assert(errors && errors->arena.beg);
  if ((errors->arena.end - errors->arena.beg) <
      ((Iz)sizeof(Err) + message.len + (1 << 8))) {
    errors_get_max_severity_and_reset(); // REVIEW: force flush errors to stderr?
    emit_err(3, s8("Exceeded error memory limit. Previous errors omitted."));
  }
  Err *err = new(&errors->arena, Err, 1);
  err->severity = severity;
  err->message = s8dup(&errors->arena, message);
  err->next = errors->first;
  errors->first = err;
  if (severity > errors->max_severity) {
    errors->max_severity = severity;
  }
  return err;
}

#define emit_errno(scratch, ...)                                               \
  do {                                                                         \
    S8 msg = {0};                                                              \
    msg = s8concat(&scratch, msg, __VA_ARGS__, s8(": "),                       \
                   s8cstr(&scratch, strerror(errno)));                         \
    emit_err(3, msg);                                                          \
  } while (0);


////////////////////////////////////////////////////////////////////////////////
//- File I/O

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static void xwrite(Arena scratch, int fd, S8 content) {
  if (content.data && content.len) {
    while (content.len > 0) {
      Iz m = content.len;
      Iz nbyte = 0;
      do {
        nbyte = write(fd, content.data, m);
      } while (nbyte < 0 && errno == EINTR);
      if (nbyte < 0) {
        emit_errno(scratch, s8("write"));
        return;
      }
      content.data += nbyte;
      content.len -= nbyte;
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
//- Program

#include <sys/signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HEAP_CAP (1u << 28)

__thread struct ErrList *errors;
static volatile int should_exit = 0;

#include "generated_metadata.h"

typedef struct {
  Post *posts;
  Iz posts_count;
} WebsiteData;

static WebsiteData data = {
  .posts = static_posts,
  .posts_count = countof(static_posts),
};

static void signal_handler(int sig) {
  (void)sig;
  should_exit = 1;
}

static int socket_bind_listen(Arena scratch, unsigned short port, int n_backlog) {
  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0) {
    emit_errno(scratch, s8("socket"));
    return 0;
  }

  int enable_reuse = 1;
  if ((setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable_reuse, sizeof(enable_reuse))) < 0) {
    emit_errno(scratch, s8("setsockopt"));
    goto err_op;
  }
  if ((setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse))) < 0) {
    emit_errno(scratch, s8("setsockopt"));
    goto err_op;
  }

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);       // Convert to network byte order
  server_addr.sin_addr.s_addr = INADDR_ANY; // Bind to all interfaces

  if ((bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0) {
    emit_errno(scratch, s8("bind"));
    goto err_op;
  }

  if ((listen(sock_fd, n_backlog)) < 0) {
    emit_errno(scratch, s8("listen"));
    goto err_op;
  }

  return sock_fd;

err_op:
  close(sock_fd);
  return 0;
}

static S8 begin_page(Arena *arena) {
  S8 s = {};

  s = s8concat(arena, s, s8("<!DOCTYPE html>\n"));
  s = s8concat(arena, s, s8("<html lang=\"en\">\n"));

  s = s8concat(arena, s, s8("<head>\n"));
  s = s8concat(arena, s, s8("  <meta charset=\"UTF-8\">\n"));

  s = s8concat(arena, s, s8("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"));
  s = s8concat(arena, s, s8("  <title>hakanssn</title>\n"));
  s = s8concat(arena, s, s8("  <meta name=\"description\" content=\"hakanssn personal website, portfolio, and blog\">\n"));
  S8 font_awesome = s8("<link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.2/css/all.min.css\"\n  integrity=\"sha512-HK5fgLBL+xu6dm/Ii3z4xhlSUyZgTT9tuc/hSrtw6uzJOvgRr2a9jyxxT1ely+B+xFAmJKVSTbpM/CuL7qxO8w==\"\n  crossorigin=\"anonymous\"/>\n");
  s = s8concat(arena, s, font_awesome);
  s = s8concat(arena, s, s8("<link rel=\"stylesheet\" href=\"/style.css\" />\n"));

  s = s8concat(arena, s, s8("</head>\n"));

  s = s8concat(arena, s, s8("<body>\n"));
  s = s8concat(arena, s, s8("<div class=\"box\">\n"));
  s = s8concat(arena, s, s8("<div class=\"center\">\n"));
  s = s8concat(arena, s, s8("<div class=\"stack\">\n"));

  s = s8concat(arena, s,
           s8("<header class=\"box bg:accent\">\n"),
           s8("<div class=\"cluster justify-content:space-between\">\n"),
           s8("<a href=\"/\"><img src=\"/logo.png\" alt=\"logo\" style=\"max-height: 52px;\"/></a>\n"),
           s8("<nav class=\"cluster\">\n"),
           s8("<a href=\"/post\">Posts</a>\n"),
           s8("<a href=\"https://github.com/AntonHakansson\">Github</a>\n"),
           s8("</nav>\n"),
           s8("</div>\n"),
           s8("</header>\n"));

  return s;
}

static S8 end_page(Arena *arena, S8 s) {
  s = s8concat(arena, s,
    s8("<footer class=\"box bg:accent\">\n"),
    s8("    <div class=\"cluster\">\n"),
    s8("        <span class=\"with-icon\">\n"),
    s8("            <i class=\"icon fab fa-github\"></i>\n"),
    s8("            <a href=\"https://github.com/AntonHakansson/\">Github</a>\n"),
    s8("        </span>\n"),
    s8("\n"),
    s8("        <span class=\"with-icon\">\n"),
    s8("            <i class=\"icon fas fa-envelope\"></i>\n"),
    s8("            <a href=\"mailto:anton@hakanssn.com\">Contact</a>\n"),
    s8("        </span>\n"),
    s8("\n"),
    /* s8("        <span class=\"with-icon\">\n"), */
    /* s8("            <i class=\"icon fas fa-rss\"></i>\n"), */
    /* s8("            <a href=\"hakanssn.com/rss\">Subscribe</a>\n"), */
    /* s8("        </span>\n"), */
    /* s8("\n"), */
    s8("        <span class=\"with-icon\">\n"),
    s8("            <i class=\"icon fas fa-code\"></i>\n"),
    s8("            <a href=\"https://github.com/AntonHakansson/hakanssn.com\">View source</a>\n"),
    s8("        </span>\n"),
    s8("        <p>Built with custom HTTP server © 2025</p>\n"),
    s8("    </div>\n"),
    s8("</footer>\n"));

  s = s8concat(arena, s, s8("</div>\n"));
  s = s8concat(arena, s, s8("</div>\n"));
  s = s8concat(arena, s, s8("</div>\n"));

  s = s8concat(arena, s, s8("</body>\n"));
  s = s8concat(arena, s, s8("</html>\n"));
  return s;
}

static S8 get_posts_listing(Arena *arena, WebsiteData data, Iz count) {
  S8 s = {};
  for (Iz i = 0; i < data.posts_count && i < count; i++) {
    Post *post = &data.posts[i];
    s = s8concat(arena, s,
                 s8("<div>\n"),
                 s8("<div class=\"cluster justify-content:space-between\">\n"),
                 s8("<h3 class=\"m0\"><a href=\"/post/"), post->slug, s8("\">"), post->title, s8("</a></h3>\n"),
                 s8("<div class=\"cluster tags space-s-1\">\n"));
    for (Iz tag_i = 0; tag_i < post->tags_count; tag_i++) {
      s = s8concat(arena, s,
                   s8("<span>"), post->tags[tag_i], s8("</span>\n"));
    }
    s = s8concat(arena, s,
                 s8("</div>\n"),
                 s8("</div>\n"),
                 s8("<span class=\"with-icon font-size:small\">\n"),
                 s8(""), post->created_at, s8("\n"),
                 s8("</span>\n"),
                 s8("<p>"), post->summary, s8("</p>\n"),
                 s8("</div>\n"));
  }
  return s;
}

static S8 home_page(Arena *arena, WebsiteData data) {
  S8 s = {};
  s = begin_page(arena);
  
  s = s8concat(arena, s,
               s8("<section>\n"
                 "<h1>About</h1>\n"
                 "<p>This is a modest personal website where I write about tech, linux tinkering, and showcase projects.</p>\n"
                 "</section>\n"));

  s = s8concat(arena, s,
               s8("<section>\n"),
               s8("    <h1 class=\"with-icon\">Posts</h1>\n"),
               s8("    <div class=\"stack\">\n"));
  s = s8concat(arena, s, get_posts_listing(arena, data, 5));
  s = s8concat(arena, s,
               s8("        <a href=\"/post\">⬇ See more posts</a>\n"),
               s8("    </div>\n"),
               s8("</section>\n"));

  s = end_page(arena, s);
  return s;
}

static S8 posts_page(Arena *arena, WebsiteData data, S8 tags[16], Iz tags_count) {
  (void)tags, (void)tags_count;
  S8 s = {};
  s = begin_page(arena);

  s = s8concat(arena, s,
               s8("<section>\n"),
               s8("    <h1 class=\"with-icon\">Posts</h1>\n"),
               s8("    <div class=\"stack\">\n"));
  s = s8concat(arena, s, get_posts_listing(arena, data, 128));
  s = s8concat(arena, s,
               s8("        <a href=\"/post\">⬇ See more posts</a>\n"),
               s8("    </div>\n"),
               s8("</section>\n"));

  s = end_page(arena, s);
  return s;
}

static S8 post_page(Arena *arena, Post *post) {
  S8 s = begin_page(arena);
  s = s8concat(arena, s, s8("<section>\n"));
  s = s8concat(arena, s, post->html_content);
  s = s8concat(arena, s, s8("</section>\n"));
  s = end_page(arena, s);
  return s;
}

typedef struct {
  S8 path;
} Client_Request;

static Client_Request parse_client_request(S8 request) {
  Client_Request r = {0};
  r.path = s8("/");

  S8pair linecut = { {}, request};
  while ((linecut = s8cut(linecut.tail, '\n')).head.data) {
    if (s8startswith(linecut.head, s8("GET "))) {
      S8pair get_parts = {{}, linecut.head};
      get_parts = s8cut(get_parts.tail, ' '); // discard GET
      get_parts = s8cut(get_parts.tail, ' ');
      _Bool is_valid_path(S8 s) {
        // Only allow a-z, ., -, and /
        _Bool valid = 0;
        for (Iz i = 0; i < s.len; i++) {
          _Bool is_alpha_lower = s.data[i] >= 'a' && s.data[i] <= 'z';
          valid = is_alpha_lower || s.data[i] == '/' || s.data[i] == '.' || s.data[i] == '-';
          if (!valid) return 0;
        }
        return valid;
      }
      if (is_valid_path(get_parts.head)) {
        r.path = get_parts.head;
      }
      else {
        printf("[DEBUG]: Client wants invalid resource: '%.*s'\n", s8pri(get_parts.head));
      }
      break; // REVIEW: Remove break statement if we ever parse more than GET header
    }
  }

  return r;
}

static S8 route_response(Arena *arena, Client_Request request) {
  S8 response = {};

  for (Iz i = 0; i < countof(static_route_mapping); i++) {
    StaticRouteMapping *resource = &static_route_mapping[i];
    if (s8equal(request.path, resource->path)) {
      response =
        s8concat(arena, s8("HTTP/1.1 200 OK\r\n"),
                 s8("Content-Type: "), resource->content_type, s8("\r\n"),
                 s8("Content-Length: "), s8i64(arena, resource->content.len), s8("\r\n"),
                 s8("Connection: close\r\n"),
                 s8("Cache-Control: public, max-age=86400\r\n"), // Cache for 1 day
                 s8("\r\n"),
                 resource->content);
      return response;
    }
  }

  S8 status_code_s = s8("200 OK");
  S8 content = {0};

  if (s8equal(request.path, s8("/")) || s8equal(request.path, s8("/index.html"))) {
    content = home_page(arena, data);
  }
  else if (s8equal(request.path, s8("/post"))) {
    content = posts_page(arena, data, 0, 0);
  }
  else if (s8startswith(request.path, s8("/post/"))) {
    S8 request_post = {0}; {
      S8pair slug_cut = s8cut(request.path, '/');
      slug_cut = s8cut(slug_cut.tail, '/');
      slug_cut = s8cut(slug_cut.tail, '/');
      request_post = slug_cut.head;
    }
    for (Iz post_i = 0; post_i < data.posts_count; post_i++) {
      Post *post = &data.posts[post_i];
      if (s8equal(post->slug, request_post)) {
        content = post_page(arena, post);
      }
    }
  }
  else {
    status_code_s = s8("404 Not Found");
    content
      = s8concat(arena,
                 s8("<!DOCTYPE html>\n"),
                 s8("<html><head><title>404 Not Found</title></head>\n"),
                 s8("<body><h1>404 Not Found</h1>\n"),
                 s8("<p>The requested resource was not found.</p></body></html>\n"));
  }

  S8 result = s8concat(arena, s8("HTTP/1.1 "), status_code_s, s8("\r\n"),
               s8("Content-Type: text/html; charset=UTF-8\r\n"),
               s8("Content-Length: "), s8i64(arena, content.len), s8("\r\n"),
               s8("Connection: close\r\n"),
               s8("X-Content-Type-Options: nosniff\r\n"),
               s8("X-Frame-Options: DENY\r\n"),
               s8("\r\n"),
               content);
  return result;
}

#if !__AFL_COMPILER

int main(int argc, char **argv)
{
  (void) argc, (void) argv;
  U8 *heap = malloc(HEAP_CAP);
  Arena arena[1] = { (Arena){heap, heap + HEAP_CAP}, };

  errors = errors_make(arena, 1 << 12);

  int sock_fd = socket_bind_listen(*arena, 8000, 128);
  {
    for_errors(err) { fprintf(stderr, "[ERROR]: %.*s\n", s8pri(err->message)); }
    int status_code = 0;
    if ((status_code = errors_get_max_severity_and_reset())) return status_code;
  }

  signal(SIGINT,  signal_handler);  // Ctrl+C
  signal(SIGTERM, signal_handler);  // kill command

  while (!should_exit) {
    Arena conn_arena = *arena;

    int fd = accept(sock_fd, 0, 0);
    if (fd < 0) { emit_errno(conn_arena, s8("accept")); }

    Client_Request client_request = {0}; {
      Iz read_buffer_len = 1024;
      U8 *read_buffer = new(&conn_arena, U8, 1024);
      ssize_t nbyte = read(fd, read_buffer, read_buffer_len);
      client_request = parse_client_request((S8){read_buffer, nbyte});
    }
    S8 response = route_response(&conn_arena, client_request);
    xwrite(conn_arena, fd, response);

    for_errors(err) { fprintf(stderr, "[ERROR]: %.*s\n", s8pri(err->message)); }
    if (errors_get_max_severity_and_reset() == 0) {
      printf("[DEBUG]: Client gets resource: '%.*s'\n", s8pri(client_request.path));
      printf("[DEBUG]: Request Memory Usage: %ld\n",
             (conn_arena.beg - arena->beg) + (arena->end - conn_arena.end));
    }

    close(fd);
  }

  close(sock_fd);

  for_errors(err) { fprintf(stderr, "[ERROR]: %.*s\n", s8pri(err->message)); }
  return !!errors_get_max_severity_and_reset();
}
#endif


#ifdef __AFL_COMPILER

#include <sys/mman.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main() {
  __AFL_INIT();
  U8 *heap = malloc(HEAP_CAP);
  Arena arena[1] = { (Arena){heap, heap + HEAP_CAP}, };
  errors = errors_make(arena, 1 << 12);

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    Client_Request client_request = parse_client_request((S8){buf, len});
    S8 response = route_response(arena, client_request);
    for_errors(err) {
      fprintf(stderr, "[ERROR]: %.*s\n", s8pri(err->message));
    }
    errors_get_max_severity_and_reset();
  }
}

#endif
