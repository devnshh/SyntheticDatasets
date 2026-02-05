importCode("debug_snippet.cpp")
println("--- Template 1 (Failed Query) ---")
val sources1 = cpg.call.name("fgets|recv|getenv|scanf|gets").argument.l
val sinks1 = cpg.call.name("strcpy|sprintf|strcat|memcpy|gets").argument.l
println("Template 1 Result: " + sinks1.reachableByFlows(sources1).l)

println("\n--- Template 3 (Parameter Source) ---")
println("Template 3 Result: " + cpg.call("strcpy").where(_.argument(2).reachableBy(cpg.parameter)).l)
