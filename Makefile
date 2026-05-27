CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra

IMGUI_DIR = imgui
SOURCES = main.cpp \
    $(IMGUI_DIR)/imgui.cpp \
    $(IMGUI_DIR)/imgui_draw.cpp \
    $(IMGUI_DIR)/imgui_tables.cpp \
    $(IMGUI_DIR)/imgui_widgets.cpp \
    $(IMGUI_DIR)/backends/imgui_impl_sdl2.cpp \
    $(IMGUI_DIR)/backends/imgui_impl_opengl3.cpp

INCLUDES = -I$(IMGUI_DIR) -I$(IMGUI_DIR)/backends

LIBS = $(shell sdl2-config --libs) -lGL -lGLEW

SDL_FLAGS = $(shell sdl2-config --cflags)

TARGET = netmon

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SDL_FLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
