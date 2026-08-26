# Chart contract

Final surface: three static PNG charts fitted without cropping into the existing
Google Slides evidence frame. Palette uses neutral grey for reactive mode and a
single green root for proactive mode; line markers and direct labels preserve
the distinction without color.

1. `chart_mechanism.png`
   - Question: does the proactive buffer keep service threads away from reclaim?
   - Takeaway: proactive starts with runway and records no Memcached memory PSI;
     reactive stays at `memory.high` and accumulates stalls.
   - Form: two aligned 20-second median-and-range line charts over four matched
     high-load pairs.
2. `chart_same_load.png`
   - Question: at identical concurrency, what changes for throughput and tail?
   - Takeaway: throughput is directionally positive but variable; worst-op
     p99.99 improves in every pair.
   - Form: paired slope plots with exact profile labels and a focused latency
     scale explicitly disclosed.
3. `chart_slo_capacity.png`
   - Question: what is the highest tested load that meets GET and SET p99.9 at
     or below 1.7 ms in every replication?
   - Takeaway: proactive qualifies at the 32+32 profile; reactive qualifies only
     at 16+16, yielding about 13% more combined throughput.
   - Form: zero-based two-bar capacity comparison with exact values and pass
     counts.
