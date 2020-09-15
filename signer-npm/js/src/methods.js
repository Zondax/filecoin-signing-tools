const MethodInit = {
  Constructor: 1,
  Exec: 2,
};

const MethodMultisig = {
  Constructor: 1,
  Propose: 2,
  Approve: 3,
  Cancel: 4,
  AddSigner: 5,
  RemoveSigner: 6,
  SwapSigner: 7,
  ChangeNumApprovalsThreshold: 8,
};

const MethodPaych = {
  Constructor: 1,
  UpdateChannelState: 2,
  Settle: 3,
  Collect: 4,
};

module.exports = {
  MethodInit,
  MethodMultisig,
  MethodPaych,
};
