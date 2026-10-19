NAME    := nineS
LIB     := lib$(NAME).a

override PLATFORM := $(strip $(subst PS5,ps5,$(subst PS4,ps4,$(PLATFORM))))

ifeq ($(PLATFORM),)

SDKS := $(strip $(if $(PS4_PAYLOAD_SDK),ps4) $(if $(PS5_PAYLOAD_SDK),ps5))

.PHONY: all ps4 ps5 clean

all:
	@test -n "$(SDKS)" || { \
		echo "Neither PS4_PAYLOAD_SDK nor PS5_PAYLOAD_SDK is defined" >&2; \
		exit 1; }
	@for platform in $(SDKS); do \
		$(MAKE) --no-print-directory PLATFORM=$$platform all || exit 1; \
	done

ps4 ps5:
	@$(MAKE) --no-print-directory PLATFORM=$@ all

clean:
	rm -rf build

else ifeq ($(PLATFORM),ps4)

ifndef PS4_PAYLOAD_SDK
    $(error PS4_PAYLOAD_SDK is undefined)
endif

include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk

ELFLDR_DIR ?= ../ps4-elfldr

ifeq ($(wildcard $(ELFLDR_DIR)/elfldr.h),)
    $(error $(ELFLDR_DIR)/elfldr.h not found; set ELFLDR_DIR to a ps4-elfldr checkout)
endif

ARCH     := -mstackrealign
EXTRAINC := -I$(ELFLDR_DIR)

else ifeq ($(PLATFORM),ps5)

ifndef PS5_PAYLOAD_SDK
    $(error PS5_PAYLOAD_SDK is undefined)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

ELFLDR_DIR ?= ../ps5-elfldr

ifeq ($(wildcard $(ELFLDR_DIR)/elfldr.h),)
    $(error $(ELFLDR_DIR)/elfldr.h not found; set ELFLDR_DIR to a ps5-elfldr checkout)
endif

ARCH     :=
EXTRAINC := -I$(ELFLDR_DIR)

else

$(error Unknown PLATFORM '$(PLATFORM)', expected ps4 or ps5)

endif

ifneq ($(PLATFORM),)

PTRACE_DIR ?= ../lib-ps-ptrace

ifeq ($(wildcard $(PTRACE_DIR)/include/ptrace.h),)
    $(error $(PTRACE_DIR)/include/ptrace.h not found; set PTRACE_DIR to a lib-ps-ptrace checkout)
endif

SOURCES := $(wildcard src/*.cpp)
BUILD   ?= build/$(PLATFORM)
OPT     ?= -O2
OBJECTS := $(SOURCES:src/%.cpp=$(BUILD)/%.o)
CXXFLAGS := -std=c++2b $(OPT) $(ARCH) -fPIC -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections
CXXFLAGS += -Wall -Werror -Iinclude -Isrc -I$(PTRACE_DIR)/include $(EXTRAINC) -MMD -MP $(if $(DEBUG),-g)

.PHONY: all clean

all: $(BUILD)/$(LIB)

$(BUILD)/$(LIB): $(OBJECTS)
	@mkdir -p $(dir $@)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD)/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD)

-include $(OBJECTS:.o=.d)

endif
