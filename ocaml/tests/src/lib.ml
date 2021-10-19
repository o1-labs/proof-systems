let () = 
  let b = Bindings.new_t () in  
  assert (b.inner = "Hello");
  let c = b.inner in
  assert (c = "Hello")
  