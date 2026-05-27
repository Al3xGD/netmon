#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_sdl2.h"
#include "imgui/backends/imgui_impl_opengl3.h"

#include <SDL2/SDL.h>
#include <GL/glew.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <set>
#include <dirent.h>
#include <unistd.h>

// ─── Data Structures ──────────────────────────────────────────────────────────

enum class ConnState {
    ESTABLISHED, LISTEN, TIME_WAIT, CLOSE_WAIT,
    SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2,
    LAST_ACK, CLOSING, UNKNOWN
};

static const char* StateStr(ConnState s) {
    switch(s) {
        case ConnState::ESTABLISHED: return "ESTABLISHED";
        case ConnState::LISTEN:      return "LISTEN";
        case ConnState::TIME_WAIT:   return "TIME_WAIT";
        case ConnState::CLOSE_WAIT:  return "CLOSE_WAIT";
        case ConnState::SYN_SENT:    return "SYN_SENT";
        case ConnState::SYN_RECV:    return "SYN_RECV";
        case ConnState::FIN_WAIT1:   return "FIN_WAIT1";
        case ConnState::FIN_WAIT2:   return "FIN_WAIT2";
        case ConnState::LAST_ACK:    return "LAST_ACK";
        case ConnState::CLOSING:     return "CLOSING";
        default:                     return "UNKNOWN";
    }
}

static ConnState ParseState(const std::string& hex) {
    // /proc/net/tcp states are hex encoded
    int v = 0;
    sscanf(hex.c_str(), "%x", &v);
    switch(v) {
        case 1:  return ConnState::ESTABLISHED;
        case 2:  return ConnState::SYN_SENT;
        case 3:  return ConnState::SYN_RECV;
        case 4:  return ConnState::FIN_WAIT1;
        case 5:  return ConnState::FIN_WAIT2;
        case 6:  return ConnState::TIME_WAIT;
        case 8:  return ConnState::CLOSE_WAIT;
        case 9:  return ConnState::LAST_ACK;
        case 10: return ConnState::LISTEN;
        case 11: return ConnState::CLOSING;
        default: return ConnState::UNKNOWN;
    }
}

static ImVec4 StateColor(ConnState s) {
    switch(s) {
        case ConnState::ESTABLISHED: return ImVec4(0.20f, 0.85f, 0.45f, 1.0f);
        case ConnState::LISTEN:      return ImVec4(0.25f, 0.65f, 1.00f, 1.0f);
        case ConnState::TIME_WAIT:   return ImVec4(0.90f, 0.70f, 0.10f, 1.0f);
        case ConnState::CLOSE_WAIT:  return ImVec4(0.90f, 0.45f, 0.10f, 1.0f);
        case ConnState::SYN_SENT:    return ImVec4(0.80f, 0.80f, 0.20f, 1.0f);
        case ConnState::SYN_RECV:    return ImVec4(0.70f, 0.80f, 0.20f, 1.0f);
        default:                     return ImVec4(0.60f, 0.60f, 0.60f, 1.0f);
    }
}

struct Connection {
    std::string proto;       // TCP / UDP
    std::string local_ip;
    int         local_port;
    std::string remote_ip;
    int         remote_port;
    ConnState   state;
    int         pid;
    std::string process_name;
    
    // Derived
    bool is_incoming() const {
        return state == ConnState::LISTEN || remote_port == 0;
    }
    bool is_outgoing() const {
        return state == ConnState::ESTABLISHED && !is_incoming();
    }
    std::string key() const {
        return proto + local_ip + std::to_string(local_port) +
               remote_ip + std::to_string(remote_port);
    }
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

static std::string hex_to_ip(const std::string& hex) {
    unsigned int ip = 0;
    sscanf(hex.c_str(), "%x", &ip);
    unsigned char a = ip & 0xFF;
    unsigned char b = (ip >> 8) & 0xFF;
    unsigned char c = (ip >> 16) & 0xFF;
    unsigned char d = (ip >> 24) & 0xFF;
    char buf[32];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", a, b, c, d);
    return std::string(buf);
}

static int hex_to_port(const std::string& hex) {
    int p = 0;
    sscanf(hex.c_str(), "%x", &p);
    return p;
}

static std::string get_process_name(int pid) {
    if (pid <= 0) return "-";
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    std::ifstream f(path);
    if (!f.is_open()) return "-";
    std::string name;
    std::getline(f, name);
    // trim
    while (!name.empty() && (name.back() == '\n' || name.back() == '\r'))
        name.pop_back();
    return name.empty() ? "-" : name;
}

// Build inode→pid map by scanning /proc/*/fd/
static std::map<int,int> build_inode_pid_map() {
    std::map<int,int> m;
    FILE* dp = popen("ls /proc/ 2>/dev/null", "r");
    if (!dp) return m;
    char line[64];
    while (fgets(line, sizeof(line), dp)) {
        int pid = atoi(line);
        if (pid <= 0) continue;
        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
        DIR* dfd = opendir(fdpath);  // We'll use readlink manually
        if (!dfd) continue;
        // Use readlink on each fd
        // Actually just call ls -la approach via /proc/pid/net isn't needed
        // We use a simpler: parse /proc/pid/net/tcp won't have pid directly
        // So we check symlinks
        struct dirent* de;
        while ((de = readdir(dfd)) != NULL) {
            if (de->d_name[0] == '.') continue;
            char lpath[128], target[256];
            snprintf(lpath, sizeof(lpath), "/proc/%d/fd/%s", pid, de->d_name);
            ssize_t len = readlink(lpath, target, sizeof(target)-1);
            if (len < 0) continue;
            target[len] = '\0';
            // target looks like "socket:[12345]"
            int inode = 0;
            if (sscanf(target, "socket:[%d]", &inode) == 1) {
                m[inode] = pid;
            }
        }
        closedir(dfd);
    }
    pclose(dp);
    return m;
}



static std::vector<Connection> parse_proc_net(const std::string& filename,
                                               const std::string& proto,
                                               const std::map<int,int>& inode_pid)
{
    std::vector<Connection> conns;
    std::ifstream f(filename);
    if (!f.is_open()) return conns;
    std::string line;
    std::getline(f, line); // skip header
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string sl, local_addr, remote_addr, state_hex;
        std::string dummy, inode_str;
        // Format: sl local_address rem_address st tx:rx_queue tr:tm->when retrnsmt uid timeout inode
        ss >> sl >> local_addr >> remote_addr >> state_hex;
        ss >> dummy >> dummy >> dummy >> dummy >> dummy >> inode_str;

        if (local_addr.empty()) continue;

        auto colon_l = local_addr.find(':');
        auto colon_r = remote_addr.find(':');
        if (colon_l == std::string::npos || colon_r == std::string::npos) continue;

        Connection c;
        c.proto       = proto;
        c.local_ip    = hex_to_ip(local_addr.substr(0, colon_l));
        c.local_port  = hex_to_port(local_addr.substr(colon_l+1));
        c.remote_ip   = hex_to_ip(remote_addr.substr(0, colon_r));
        c.remote_port = hex_to_port(remote_addr.substr(colon_r+1));
        c.state       = (proto == "UDP") ? ConnState::ESTABLISHED : ParseState(state_hex);

        int inode = atoi(inode_str.c_str());
        auto it = inode_pid.find(inode);
        if (it != inode_pid.end()) {
            c.pid          = it->second;
            c.process_name = get_process_name(c.pid);
        } else {
            c.pid          = -1;
            c.process_name = "-";
        }

        conns.push_back(c);
    }
    return conns;
}

// ─── Monitor Thread ───────────────────────────────────────────────────────────

struct AppState {
    std::mutex              mtx;
    std::vector<Connection> connections;
    std::atomic<bool>       running{true};
    std::atomic<int>        refresh_ms{1500};

    // Stats
    int total = 0, established = 0, listening = 0, time_wait = 0;

    // History for sparklines (established count over last 60 samples)
    static const int HISTORY = 60;
    float hist_established[HISTORY] = {};
    float hist_listening[HISTORY]   = {};
    int   hist_idx = 0;
};

static void monitor_thread(AppState* app) {
    while (app->running.load()) {
        auto inode_pid = build_inode_pid_map();

        std::vector<Connection> all;
        auto tcp  = parse_proc_net("/proc/net/tcp",  "TCP",  inode_pid);
        auto tcp6 = parse_proc_net("/proc/net/tcp6", "TCP6", inode_pid);
        auto udp  = parse_proc_net("/proc/net/udp",  "UDP",  inode_pid);
        all.insert(all.end(), tcp.begin(),  tcp.end());
        all.insert(all.end(), tcp6.begin(), tcp6.end());
        all.insert(all.end(), udp.begin(),  udp.end());

        // Sort: ESTABLISHED first, then LISTEN, etc.
        std::sort(all.begin(), all.end(), [](const Connection& a, const Connection& b) {
            return (int)a.state < (int)b.state;
        });

        int est=0, lst=0, tw=0;
        for (auto& c : all) {
            if (c.state == ConnState::ESTABLISHED) est++;
            else if (c.state == ConnState::LISTEN) lst++;
            else if (c.state == ConnState::TIME_WAIT) tw++;
        }

        {
            std::lock_guard<std::mutex> lk(app->mtx);
            app->connections = std::move(all);
            app->total       = (int)app->connections.size();
            app->established = est;
            app->listening   = lst;
            app->time_wait   = tw;
            app->hist_established[app->hist_idx % AppState::HISTORY] = (float)est;
            app->hist_listening  [app->hist_idx % AppState::HISTORY] = (float)lst;
            app->hist_idx++;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(app->refresh_ms.load()));
    }
}

// ─── UI Helpers ───────────────────────────────────────────────────────────────

static void StatCard(const char* label, int value, ImVec4 color, ImVec2 size) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.08f,0.08f,0.10f,1.f));
    ImGui::BeginChild(label, size, true);
    ImGui::PushStyleColor(ImGuiCol_Text, color);
    ImGui::SetWindowFontScale(1.8f);
    ImGui::Text("%d", value);
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();
    ImGui::TextDisabled("%s", label);
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

static char g_filter[256] = "";
static bool g_show_tcp  = true;
static bool g_show_tcp6 = true;
static bool g_show_udp  = true;
static int  g_state_filter = 0; // 0=all,1=established,2=listen,3=other

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int, char**) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
        fprintf(stderr, "SDL_Init error: %s\n", SDL_GetError());
        return 1;
    }

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);

    SDL_WindowFlags wf = (SDL_WindowFlags)(SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    SDL_Window* window = SDL_CreateWindow(
        "NetMon — Monitor de Conexiones",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        1280, 800, wf
    );
    SDL_GLContext gl_ctx = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_ctx);
    SDL_GL_SetSwapInterval(1);

    if (glewInit() != GLEW_OK) {
        fprintf(stderr, "GLEW init failed\n");
        return 1;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // ── Style ──
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding    = 6.0f;
    style.ChildRounding     = 4.0f;
    style.FrameRounding     = 4.0f;
    style.PopupRounding     = 4.0f;
    style.ScrollbarRounding = 4.0f;
    style.GrabRounding      = 4.0f;
    style.TabRounding       = 4.0f;
    style.WindowBorderSize  = 0.0f;
    style.FrameBorderSize   = 0.0f;
    style.ItemSpacing       = ImVec2(8, 6);
    style.FramePadding      = ImVec2(8, 4);
    style.WindowPadding     = ImVec2(14, 14);

    // Custom dark palette
    auto& c = style.Colors;
    c[ImGuiCol_WindowBg]          = ImVec4(0.05f,0.05f,0.07f,1.f);
    c[ImGuiCol_Header]            = ImVec4(0.15f,0.15f,0.20f,1.f);
    c[ImGuiCol_HeaderHovered]     = ImVec4(0.20f,0.20f,0.28f,1.f);
    c[ImGuiCol_HeaderActive]      = ImVec4(0.25f,0.40f,0.70f,1.f);
    c[ImGuiCol_FrameBg]           = ImVec4(0.10f,0.10f,0.14f,1.f);
    c[ImGuiCol_FrameBgHovered]    = ImVec4(0.15f,0.15f,0.20f,1.f);
    c[ImGuiCol_Button]            = ImVec4(0.15f,0.15f,0.22f,1.f);
    c[ImGuiCol_ButtonHovered]     = ImVec4(0.25f,0.35f,0.60f,1.f);
    c[ImGuiCol_ButtonActive]      = ImVec4(0.20f,0.45f,0.80f,1.f);
    c[ImGuiCol_Tab]               = ImVec4(0.10f,0.10f,0.14f,1.f);
    c[ImGuiCol_TabHovered]        = ImVec4(0.20f,0.30f,0.55f,1.f);
    c[ImGuiCol_TabActive]         = ImVec4(0.18f,0.35f,0.65f,1.f);
    c[ImGuiCol_TitleBg]           = ImVec4(0.04f,0.04f,0.06f,1.f);
    c[ImGuiCol_TitleBgActive]     = ImVec4(0.06f,0.10f,0.18f,1.f);
    c[ImGuiCol_CheckMark]         = ImVec4(0.25f,0.65f,1.00f,1.f);
    c[ImGuiCol_SliderGrab]        = ImVec4(0.25f,0.55f,0.90f,1.f);
    c[ImGuiCol_SliderGrabActive]  = ImVec4(0.30f,0.65f,1.00f,1.f);
    c[ImGuiCol_Separator]         = ImVec4(0.14f,0.14f,0.20f,1.f);
    c[ImGuiCol_TableBorderStrong] = ImVec4(0.14f,0.14f,0.22f,1.f);
    c[ImGuiCol_TableBorderLight]  = ImVec4(0.09f,0.09f,0.13f,1.f);
    c[ImGuiCol_TableRowBg]        = ImVec4(0.00f,0.00f,0.00f,0.00f);
    c[ImGuiCol_TableRowBgAlt]     = ImVec4(1.00f,1.00f,1.00f,0.03f);
    c[ImGuiCol_ScrollbarBg]       = ImVec4(0.04f,0.04f,0.06f,1.f);
    c[ImGuiCol_ScrollbarGrab]     = ImVec4(0.18f,0.18f,0.25f,1.f);
    c[ImGuiCol_ScrollbarGrabHovered]= ImVec4(0.24f,0.24f,0.35f,1.f);

    ImGui_ImplSDL2_InitForOpenGL(window, gl_ctx);
    ImGui_ImplOpenGL3_Init("#version 330");

    // ── Start monitor thread ──
    AppState app;
    std::thread mon(monitor_thread, &app);

    bool done = false;
    int refresh_setting = 1500;

    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) done = true;
            if (event.type == SDL_WINDOWEVENT &&
                event.window.event == SDL_WINDOWEVENT_CLOSE &&
                event.window.windowID == SDL_GetWindowID(window)) done = true;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        // ── Full-screen main window ──
        ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
        ImGui::Begin("##main", nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav);
        ImGui::PopStyleVar(2);

        // ── Header bar ──
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f,0.65f,1.f,1.f));
        ImGui::SetWindowFontScale(1.3f);
        ImGui::Text("  NETMON");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled("  Monitor de Conexiones de Red en Tiempo Real");
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 200);
        ImGui::TextDisabled("Refresh:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(120);
        if (ImGui::SliderInt("##refresh", &refresh_setting, 500, 5000, "%d ms")) {
            app.refresh_ms.store(refresh_setting);
        }
        ImGui::Separator();
        ImGui::Spacing();

        // ── Snapshot ──
        std::vector<Connection> snap;
        int total_s, est_s, lst_s, tw_s;
        float hist_est[AppState::HISTORY];
        float hist_lst[AppState::HISTORY];
        int   hist_idx_s;
        {
            std::lock_guard<std::mutex> lk(app.mtx);
            snap       = app.connections;
            total_s    = app.total;
            est_s      = app.established;
            lst_s      = app.listening;
            tw_s       = app.time_wait;
            memcpy(hist_est, app.hist_established, sizeof(hist_est));
            memcpy(hist_lst, app.hist_listening,   sizeof(hist_lst));
            hist_idx_s = app.hist_idx;
        }

        // ── Stat cards ──
        float card_w = 160.f, card_h = 68.f;
        float spacing = 12.f;
        StatCard("TOTAL",       total_s, ImVec4(0.75f,0.75f,0.85f,1.f), ImVec2(card_w, card_h));
        ImGui::SameLine(0, spacing);
        StatCard("ESTABLISHED", est_s,   ImVec4(0.20f,0.85f,0.45f,1.f), ImVec2(card_w, card_h));
        ImGui::SameLine(0, spacing);
        StatCard("LISTENING",   lst_s,   ImVec4(0.25f,0.65f,1.00f,1.f), ImVec2(card_w, card_h));
        ImGui::SameLine(0, spacing);
        StatCard("TIME_WAIT",   tw_s,    ImVec4(0.90f,0.70f,0.10f,1.f), ImVec2(card_w, card_h));
        ImGui::SameLine(0, spacing);

        // Mini sparklines
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.08f,0.08f,0.10f,1.f));
        ImGui::BeginChild("##spark", ImVec2(260, card_h), true);
        // Reorder history so oldest is first
        float ordered_est[AppState::HISTORY], ordered_lst[AppState::HISTORY];
        for (int i = 0; i < AppState::HISTORY; i++) {
            ordered_est[i] = hist_est[(hist_idx_s + i) % AppState::HISTORY];
            ordered_lst[i] = hist_lst[(hist_idx_s + i) % AppState::HISTORY];
        }
        ImGui::PushStyleColor(ImGuiCol_PlotLines, ImVec4(0.20f,0.85f,0.45f,1.f));
        ImGui::PlotLines("##est", ordered_est, AppState::HISTORY, 0, "Established", 0.f, FLT_MAX, ImVec2(110, 48));
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 8);
        ImGui::PushStyleColor(ImGuiCol_PlotLines, ImVec4(0.25f,0.65f,1.00f,1.f));
        ImGui::PlotLines("##lst", ordered_lst, AppState::HISTORY, 0, "Listening", 0.f, FLT_MAX, ImVec2(110, 48));
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::Spacing();

        // ── Filters bar ──
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.10f,0.10f,0.15f,1.f));
        ImGui::SetNextItemWidth(280);
        ImGui::InputTextWithHint("##filter", "  Filtrar por IP, puerto, proceso...", g_filter, sizeof(g_filter));
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 16);
        ImGui::Checkbox("TCP",  &g_show_tcp);  ImGui::SameLine(0,8);
        ImGui::Checkbox("TCP6", &g_show_tcp6); ImGui::SameLine(0,8);
        ImGui::Checkbox("UDP",  &g_show_udp);  ImGui::SameLine(0,16);
        ImGui::TextDisabled("|"); ImGui::SameLine(0,16);
        const char* state_items[] = {"Todos","Established","Listen","Otros"};
        ImGui::SetNextItemWidth(130);
        ImGui::Combo("Estado##filter", &g_state_filter, state_items, IM_ARRAYSIZE(state_items));
        ImGui::SameLine();
        ImGui::TextDisabled("(%zu mostrando)", snap.size());

        ImGui::Spacing();

        // ── Tabs ──
        if (ImGui::BeginTabBar("##tabs")) {
            auto render_table = [&](const char* label, int direction) {
                // direction: 0=all, 1=incoming(listen), 2=outgoing(established to remote)
                if (ImGui::BeginTabItem(label)) {
                    static ImGuiTableFlags tflags =
                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                        ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingStretchProp |
                        ImGuiTableFlags_Sortable;

                    float avail_h = ImGui::GetContentRegionAvail().y - 4;
                    if (ImGui::BeginTable("conns", 8, tflags, ImVec2(0, avail_h))) {
                        ImGui::TableSetupScrollFreeze(0, 1);
                        ImGui::TableSetupColumn("Proto",    ImGuiTableColumnFlags_WidthFixed, 52);
                        ImGui::TableSetupColumn("IP Local", ImGuiTableColumnFlags_WidthStretch, 1.4f);
                        ImGui::TableSetupColumn("Puerto",   ImGuiTableColumnFlags_WidthFixed, 62);
                        ImGui::TableSetupColumn("IP Remota",ImGuiTableColumnFlags_WidthStretch, 1.4f);
                        ImGui::TableSetupColumn("Pto.Rem.", ImGuiTableColumnFlags_WidthFixed, 62);
                        ImGui::TableSetupColumn("Estado",   ImGuiTableColumnFlags_WidthFixed, 112);
                        ImGui::TableSetupColumn("PID",      ImGuiTableColumnFlags_WidthFixed, 56);
                        ImGui::TableSetupColumn("Proceso",  ImGuiTableColumnFlags_WidthStretch, 1.0f);
                        ImGui::TableHeadersRow();

                        std::string flt(g_filter);
                        std::transform(flt.begin(), flt.end(), flt.begin(), ::tolower);

                        int row = 0;
                        for (auto& conn : snap) {
                            // Protocol filter
                            if (!g_show_tcp  && conn.proto == "TCP")  continue;
                            if (!g_show_tcp6 && conn.proto == "TCP6") continue;
                            if (!g_show_udp  && conn.proto == "UDP")  continue;

                            // Direction filter
                            if (direction == 1 && conn.state != ConnState::LISTEN)      continue;
                            if (direction == 2 && conn.state != ConnState::ESTABLISHED) continue;

                            // State combo filter
                            if (g_state_filter == 1 && conn.state != ConnState::ESTABLISHED) continue;
                            if (g_state_filter == 2 && conn.state != ConnState::LISTEN)      continue;
                            if (g_state_filter == 3 && (conn.state == ConnState::ESTABLISHED || conn.state == ConnState::LISTEN)) continue;

                            // Text filter
                            if (!flt.empty()) {
                                auto contains = [&](const std::string& s) {
                                    std::string sl = s;
                                    std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
                                    return sl.find(flt) != std::string::npos;
                                };
                                bool match = contains(conn.local_ip)  ||
                                             contains(conn.remote_ip) ||
                                             contains(conn.process_name) ||
                                             contains(std::to_string(conn.local_port)) ||
                                             contains(std::to_string(conn.remote_port));
                                if (!match) continue;
                            }

                            ImGui::TableNextRow();
                            row++;

                            ImGui::TableSetColumnIndex(0);
                            // Color-code protocol
                            ImVec4 proto_col = (conn.proto == "TCP")  ? ImVec4(0.30f,0.70f,1.00f,1.f) :
                                               (conn.proto == "TCP6") ? ImVec4(0.50f,0.80f,1.00f,1.f) :
                                                                         ImVec4(0.80f,0.65f,0.20f,1.f);
                            ImGui::PushStyleColor(ImGuiCol_Text, proto_col);
                            ImGui::TextUnformatted(conn.proto.c_str());
                            ImGui::PopStyleColor();

                            ImGui::TableSetColumnIndex(1);
                            ImGui::TextUnformatted(conn.local_ip.c_str());

                            ImGui::TableSetColumnIndex(2);
                            ImGui::Text("%d", conn.local_port);

                            ImGui::TableSetColumnIndex(3);
                            if (conn.remote_ip == "0.0.0.0" || conn.remote_port == 0)
                                ImGui::TextDisabled("—");
                            else
                                ImGui::TextUnformatted(conn.remote_ip.c_str());

                            ImGui::TableSetColumnIndex(4);
                            if (conn.remote_port == 0)
                                ImGui::TextDisabled("—");
                            else
                                ImGui::Text("%d", conn.remote_port);

                            ImGui::TableSetColumnIndex(5);
                            ImGui::PushStyleColor(ImGuiCol_Text, StateColor(conn.state));
                            ImGui::TextUnformatted(StateStr(conn.state));
                            ImGui::PopStyleColor();

                            ImGui::TableSetColumnIndex(6);
                            if (conn.pid > 0)
                                ImGui::Text("%d", conn.pid);
                            else
                                ImGui::TextDisabled("—");

                            ImGui::TableSetColumnIndex(7);
                            ImGui::TextUnformatted(conn.process_name.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }
            };

            render_table("  Todas las Conexiones  ", 0);
            render_table("  Entrantes (LISTEN)  ",   1);
            render_table("  Salientes (ESTABLISHED)  ", 2);

            ImGui::EndTabBar();
        }

        ImGui::End(); // main

        ImGui::Render();
        int w, h;
        SDL_GetWindowSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.05f, 0.05f, 0.07f, 1.f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    app.running.store(false);
    mon.join();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_ctx);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
