SUB_DIR:=$(shell echo  `uname | sed -e 's|[:/\\ \(\)]|_|g'`/`git branch | grep '\* ' | cut -f2- -d' '| sed -e 's|[:/\\ \(\)]|_|g'`)

ifeq ($(DEBUG),)
	BUILD_TYPE := Release
else
	BUILD_TYPE := Debug
endif

ifeq ($(USE_SINGLE_BUILD_DIR),)
  BUILD_DIR := build/$(SUB_DIR)/$(BUILD_TYPE)
  TOP_DIR   := ../../../..
else
  BUILD_DIR := build
  TOP_DIR   := ..
endif

ifeq ($(GEN),)
	CMAKE := cmake
else
	CMAKE := cmake -G$(GEN)
endif

BUILD_STATIC ?= ON

MKDIR := mkdir -p $(BUILD_DIR) && cd $(BUILD_DIR)

static-deps:
	$(MKDIR) && \
	$(CMAKE) \
		-DBUILD_STATIC_DEPS=ON \
		-DBoost_USE_STATIC_LIBS=$(BUILD_STATIC) \
		-DOPENSSL_USE_STATIC_LIBS=$(BUILD_STATIC) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DDISABLE_SNODE_SIGNATURE=OFF \
		$(TOP_DIR) \
		&& cmake --build .

all:
	$(MKDIR) && \
	$(CMAKE) \
		-DBoost_USE_STATIC_LIBS=$(BUILD_STATIC) \
		-DOPENSSL_USE_STATIC_LIBS=$(BUILD_STATIC) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DDISABLE_SNODE_SIGNATURE=OFF \
		$(TOP_DIR) \
		&& cmake --build .

clean:
	rm -rf build/$(SUB_DIR)

clean-all:
	rm -rf build

format:
	clang-format -style=file -i \
		crypto/**/*.{cpp,hpp} \
		storage/**/*.{cpp,hpp} \
		utils/**/*.{cpp,hpp} \
		httpserver/*.{cpp,h} \
		common/**/*.{cpp,h}

.PHONY: all clean format rebuild