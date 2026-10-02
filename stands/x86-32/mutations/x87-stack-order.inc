  // STAND32 deliberate mutant: lose the stack exchange in the lifter.
  const char* Mutation = std::getenv("STAND32_MUTATION");
  if (Mutation && std::string_view{Mutation} == "x87_stack_order") Offset = 0;
