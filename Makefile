LOG_LEVEL_DSIABLE = 4
LOG_LEVEL_ERROR = 3
LOG_LEVEL_WARN = 2
LOG_LEVEL_INFO = 1
LOG_LEVEL_DEBUG = 0

# use loge-level-error as default value
LOG_LEVEL = $(LOG_LEVEL_ERROR)
MACROS =
ifneq ($(DEBUG),)
	MACROS += -DDEBUG
	LOG_LEVEL = $(LOG_LEVEL_DEBUG)
endif
MACROS += -DLOG_LEVEL=$(LOG_LEVEL)

CFLAGS += $(MACROS) -g -fPIC -fno-omit-frame-pointer -fno-strict-aliasing -Wall -Werror -pipe

HDRPATHS = -I. $(addprefix -I, $(HDRS))
LIBPATHS = $(addprefix -L, $(LIBS))
COMMA = ,
SOPATHS = $(addprefix -Wl$(COMMA)-rpath$(COMMA), $(LIBS))
STATIC_LINKINGS =
DYNAMIC_LINKINGS = -lcrypto -pthread -lkeyutils

SRCEXTS = .c

ENGINE_DIRS = .
ENGINE_SOURCES = $(foreach d,$(ENGINE_DIRS),$(wildcard $(addprefix $(d)/*, $(SRCEXTS))))
ENGINE_OBJS = $(addsuffix .o, $(basename $(ENGINE_SOURCES)))
EXAMPLE_OBJS = $(UTILS_OBJS) example/example.o ./log.o

OBJS = $(ENGINE_OBJS) $(EXAMPLE_OBJS)

KCTL_ENGINE = lkcf-engine

.PHONY:all
all: $(KCTL_ENGINE) example

.PHONY:clean
clean:
	@echo "> Cleaning"
	rm -rf $(OBJS) example/example $(KCTL_ENGINE).so $(KCTL_ENGINE).a

.PHONY:test
test:
	OPENSSL_ENGINES=`pwd` openssl engine -t -c -v $(KCTL_ENGINE)

example:$(EXAMPLE_OBJS)
	@echo "> Linking $@"
	$(CC) -o example/example $(LIBSPATHS) $(SOPATHS) $(EXAMPLE_OBJS) $(STATIC_LINKINGS) $(DYNAMIC_LINKINGS)

%.o:%.c
	@echo "> Compiling $@"
	$(CC) -c $(CFLAGS) $(HDRPATHS) $< -o $@

$(KCTL_ENGINE):$(ENGINE_OBJS)
	@echo "> Linking $@"
	echo $(ENGINE_SOURCES)
	$(CC) -shared -o $@.so $(LIBPATHS) $(SOPATHS) -Xlinker "-(" $(ENGINE_OBJS) -Xlinker "-)" $(STATIC_LINKINGS) $(DYNAMIC_LINKINGS)
	ar rcs $@.a $^

