importCode("debug_snippet.cpp")
println("Identifying strcpy calls...")
cpg.call("strcpy").foreach { call =>
    println(s"Found strcpy at line ${call.lineNumber.getOrElse(-1)}")
    call.argument.zipWithIndex.foreach { case (arg, idx) =>
        println(s"  Arg $idx: ${arg.code} label=${arg.label}")
        if (arg.isIdentifier) {
             val id = arg.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Identifier]
             println(s"    Is Identifier. Type: ${id.typeFullName}")
             
             // TRAVERSAL CHECK
             // Check outgoing refs (Identifier -> Local)
             val refs = id.refsTo.l
             println(s"    refsTo: ${refs.map(_.label)}")
             refs.foreach { r =>
                 print(s"      Target Code: ${r.code} Label: ${r.label} ")
                 if (r.isLocal) {
                     val local = r.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Local]
                     println(s"Type: ${local.typeFullName}")
                 } else if (r.isMethodParameter) {
                      val param = r.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn]
                      println(s"Type: ${param.typeFullName}")
                 } else {
                     println("Type: Unknown Node")
                 }
             }
        }
    }
}
