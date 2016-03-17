require 'ffi/otr'

FFI::OTR.otrl_init 3, 2, 1

class OTRUserState < FFI::OTR::UserState

  # Initialize the userstate given the +client+, +account+ name, +protocol+.
   def initialize client, account, protocol, opts = {}
    @client = client
    super(account, protocol, opts)
  end

  # OTR wants to send a message
  def inject_message opdata, account, protocol, recipient, message
    @client.jabber.deliver(recipient, message)
  end

  # OTR wants to display a special message
  def display_otr_message opdata, account, protocol, from, msg
    puts "#{from}: #{msg}"
    # If the received message was not encrypted, remember the command and handle it once the session is established
    if msg =~ /<b>The following message received from #{from} was <i>not<\/i> encrypted: \[<\/b>(.+)<b>\]<\/b>/
      @gone_secure_cb = -> { @client.instance_eval { parse_command(from, $1) } }
    end
  end

  # Create a private key for the given accountname/protocol if desired.
  def create_privkey opdata, account, protocol
    return super  unless @opts[:privkey]
    puts "Generating private key. This may take a while."
    privkey_generate(@opts[:privkey], @account, @protocol)
    puts "Done. My fingerprint is: #{fingerprint}"
  end

  # Called when OTR has established a secure session.
  def gone_secure *a
    @gone_secure_cb.call  if @gone_secure_cb
  end

end
