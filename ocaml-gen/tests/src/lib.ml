let () =
  let a = Bindings.new_t () in
  Bindings.print_t a

let () = 
  let b = Bindings.new_t () in  
  assert (b.inner = "Hello")
  