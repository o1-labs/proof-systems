type nonrec single_tuple = { inner: string } [@@boxed]
external new_t : unit -> single_tuple = "new"
external print_t : single_tuple -> unit = "print"

module Car = struct 
  type nonrec t
end


module Toyota = struct 
  type nonrec t = Car.t
  external create_toyota : unit -> Car.t = "create_toyota"
end

