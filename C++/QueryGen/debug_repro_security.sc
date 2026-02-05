importCode("debug_snippet.cpp")
println("\n--- Testing Security Grade Query (Fixed Syntax) ---")

// Using .collectAll[Local] to safely cast and check typeFullName
val q = cpg.call("strcpy|strcat|sprintf").where(_.argument(1).isIdentifier.refsTo.collectAll[Local].typeFullName(".*\\[.*\\]")).where(_.argument(2).reachableBy(cpg.parameter))

println("Query Steps Breakdown:")
println("1. Base calls: " + cpg.call("strcpy|strcat|sprintf").size)

println("2. Argument 1 is (Identifier -> Local -> Array):")
cpg.call("strcpy|strcat|sprintf").argument(1).isIdentifier.refsTo.collectAll[Local].map(n => 
    (n.name, n.typeFullName)
).l.foreach(println)

println("3. Argument 2 is reachable by Parameter:")
val args2 = cpg.call("strcpy|strcat|sprintf").argument(2).l
println("Args2 found: " + args2.code.l)
val flows = args2.reachableBy(cpg.parameter).l
println("Reachable flows count: " + flows.size)

println("Full Query Result: " + q.l)
