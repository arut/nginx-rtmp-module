--[[
  Author: Neutron Soutmun <neo.neutron@gmail.com>
  Created: 2012-08-07
]]--

-- lua-socket is required
local mime = require ("mime");
local url  = require ("socket.url");
-- lua-md5 is required
local md5  = require ("md5");

local scode    = {};
local desccode = {}; local session  = {};

--[ Constant declaration ]--

scode["ALLOW"]  = "allow";
scode["DENY"]   = "deny";
scode["REJECT"] = "reject";

desccode["rejectMissingAuth"] = "[ code=403 need auth; authmod=%s ]";
desccode["invalidAuthMod"]    = "[ AccessManager.Reject ] : [ authmod=%s ] : "
                                .. "?reason=invalid_authmod&opaque=-";
desccode["noSuchUser"]        = "[ AccessManager.Reject ] : [ authmod=%s ] : "
                                .. "?reason=nosuchuser&opaque=sTQAAA=";
desccode["unauthorized"]      = "[ AccessManager.Reject ] : [ authmod=%s ] : "
                                .. "?reason=unauthorized&opaque=sTQAAA=";

--[ Sample session data ]--
session["user"]      = "neutron";
session["salt"]      = mime.b64 (md5.sum ("salt"));
session["challenge"] = mime.b64 (md5.sum ("challenge"));
session["opaque"]    = session["challenge"];
session["password"]  = "password";

--[ Settings ]--
default_auth = "adobe";
debug_enable = true;
debug_prefix = "[authen] ";

--[ Global variables ]--
desc    = "";
status  = scode["DENY"];
args    = ngx.req.get_post_args ();
urlargs = {};

function withDebug (msg)
  ngx.log (ngx.DEBUG, debug_prefix .. msg);
end

function withoutDebug (msg)
  -- Do nothing
end

debug = withDebug;
if not debug_enable then
  debug = withoutDebug;
end

--[ Functions ]--
function insertfield (args, name, value)
  if not args[name] then
    args[name] = value;
  else
    local t = type (args[name]);
    if t == "string" then
      args[name] = {args[name],value,};
    elseif t == "table" then
      table.insert (args[name], value);
    else
      error ("Fatal error (invalid args table)!");
    end
  end
end

function parseArgs (query, args)
  if type (query) == "string" then
    local unescape = url.unescape;
    string.gsub (query, "([^?&=]+)=([^&]*)&?",
    function (key, val)
      insertfield (args, unescape (key), unescape (val))
    end);
  end
end

function getArg (name)
  return urlargs[name];
end

function createDesc (type)
  if desccode[type] ~= nil then
    local authmod = getArg ("authmod");

    if type == "rejectMissingAuth" then
      authmod = default_auth;
    end

    return mime.b64 (string.format (desccode[type], authmod));
  end

  return "";
end

--[ Authen Modules ]--

-- Adobe
function setupChallenge ()
  local user = getArg ("user");
  desc = mime.b64 ("[ AccessManager.Reject ] : [ authmod=adobe ] : "
                   .. "?reason=needauth"
                   .. "&user=" .. user
                   .. "&salt=" .. session["salt"]
                   .. "&challenge=" .. session["challenge"]
                   .. "&opaque=" .. session["opaque"]);
  status = scode["REJECT"];
  debug ("-- Reject: " .. desc);
end

function verifyResponse ()
  local user      = getArg ("user");
  local challenge = getArg ("challenge");
  local opaque    = getArg ("opaque");
  local response  = getArg ("response");

  local c1 = user .. session["salt"] .. session["password"];
  local h1 = mime.b64 (md5.sum (c1));
  local c2 = h1 .. opaque .. challenge;
  local h2 = mime.b64 (md5.sum (c2));

  debug ("-- user: " .. user);
  debug ("-- challenge: " .. challenge);
  debug ("-- opaque: " .. opaque);
  debug ("-- response: " .. response);

  if response == h2 then
    status = scode["ALLOW"];
    debug ("-- Allow: Authorized");
  else
    desc = createDesc ("unauthorized");
    status = scode["REJECT"];
    debug ("-- Not match: " .. h2 .. ", " .. response);
    debug ("-- Reject: Unauthorized (" .. mime.unb64(desc) .. ")");
  end
end

function userCheck (user)
  return user == session["user"];
end

function AdobeAuthen ()
  if getArg ("response") ~= nil then
    debug ("-- Authentication Verifying");
    verifyResponse ();
  else
    if userCheck (getArg ("user")) then
      debug ("-- Setup Challenge");
      setupChallenge ();
    else
      status = scode["REJECT"];
      desc = createDesc ("noSuchUser");
      debug ("-- Reject: " .. mime.unb64 (desc));
    end
  end
end

--[ Main ]--
debug ("Authen request: " .. ngx.var.request_body);

if args["tcurl"] ~= nil then
  debug ("-- process tcurl: " .. args["tcurl"]);
  parseArgs (args["tcurl"], urlargs);
end

local authmod = getArg ("authmod");
local user    = getArg ("user");

if authmod ~= nil then
  debug ("-- authmod: " .. authmod);
end

if user ~= nil then
  if authmod == "adobe" then
    AdobeAuthen ();
  else
    status = scode["REJECT"];
    desc = createDesc ("invalidAuthMod");
    debug ("-- Reject: " .. mime.unb64 (desc));
  end
else
  status = scode["REJECT"];
  desc = createDesc ("rejectMissingAuth");
  debug ("-- Reject: " .. mime.unb64 (desc));
end

--[[ Response syntax:

  status=<status_code>&desc=<description>&user=<username>&authmod=<authmod>\r\n

  status_code = allow|deny|reject
    allow  : allow connection
    deny   : deny connection
    reject : reject connection with description report to client

  description = description for rejected connection (base64 encoded)
  user        = username (uri escaped)
  authmod     = authentication module name

]] --

response = "status=" .. status;
if desc ~= ""  then response = response .. "&desc=" .. desc; end
if user ~= nil then response = response .. "&user=" .. url.escape (user); end

if authmod ~= nil  then
  response = response .. "&authmod=" .. url.escape (authmod);
end

debug ("-- Sending response: " .. response .. "\r\n");
ngx.say (response);
