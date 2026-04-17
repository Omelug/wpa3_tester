#pragma once
#include <string>

#include "logger/log.h"

namespace wpa3_tester{
    enum class TimeAxis { RELATIVE, UNIX };
    enum class GraphElement_t { UNKNOWN, EVENT_LINES, GRAPH_XY_POINTS };
    class GraphElements {
    public:
        GraphElement_t type = GraphElement_t::UNKNOWN;
        std::string label;
        std::string color = "green";

        explicit GraphElements(std::string label, std::string color = "green")
            : label(std::move(label)), color(std::move(color)) {}

        virtual ~GraphElements() = default;
    };

    // Graph elements //TODO
    typedef std::vector<std::unique_ptr<GraphElements>>& G_el;

    class EventLines : public GraphElements{
        public:
            std::vector<LogTimePoint> event_times;

            EventLines(std::vector<LogTimePoint> event_times,
                       std::string label,
                       std::string color = "green")
                : GraphElements(std::move(label), std::move(color))
                , event_times(std::move(event_times)){
                type = GraphElement_t::EVENT_LINES;
            }

    };

    enum class YAxis { Y1, Y2 };
    class GraphXYPoints : public GraphElements{
        YAxis axis = YAxis::Y1;

    public:
        std::vector<LogTimePoint> x_times;
        std::vector<double> y_values;

        GraphXYPoints(const std::vector<LogTimePoint> &x_times, const std::vector<double> &y_values,
            const std::string &label, const std::string &color = "green")
            : GraphElements(label, color),
              x_times(x_times), y_values(y_values){
            type = GraphElement_t::GRAPH_XY_POINTS;
        }

    };

    class Graph{
    public:
        FILE* file;
        double ymin = 0;
        double ymax = 1;
        LogTimePoint start_time;
        TimeAxis axis = TimeAxis::RELATIVE;
        std::vector<std::string> plot_parts;

        void add_graph_elements(const std::vector<std::unique_ptr<GraphElements>> &elements);
        void gpcmd(const std::string &cmd) const;
        void add_XY_points(const GraphXYPoints &xy_points);
        void add_event_lines(EventLines &event_lines, size_t &event_block_index, size_t event_size, size_t &label_index);
        void render();
    };

}