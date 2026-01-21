local mathx = require("mathx")

local function run()
  local x = mathx.add(1, 2)
  local y = mathx.mul(x, 3)
  return y
end

print(run())
