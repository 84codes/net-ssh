require 'net/ssh/errors'
require 'net/ssh/known_hosts'

module Net
  module SSH
    module Verifiers
      # Does a strict host verification, looking the server up in the known
      # host files to see if a key has already been seen for this server. If this
      # server does not appear in any host file, an exception will be raised
      # (HostKeyUnknown). This is in contrast to the "Strict" class, which will
      # silently add the key to your known_hosts file. If the server does appear at
      # least once, but the key given does not match any known for the server, an
      # exception will be raised (HostKeyMismatch).
      # Otherwise, this returns true.
      class Always
        def verify(arguments)
          host_keys = arguments[:session].host_keys

          # We've never seen this host before, so raise an exception.
          process_cache_miss(host_keys, arguments, HostKeyUnknown, "is unknown") if host_keys.empty?


          # If we found any matches, check to see that the key type and
          # blob also match.
          found_keys = host_keys.find do |key|
            if key.respond_to?(:matches_key?)
              key.matches_key?(arguments[:key])
            else
              key.ssh_type == arguments[:key].ssh_type && key.to_blob == arguments[:key].to_blob
            end
          end

          # If a match was found, return true. Otherwise, raise an exception
          # indicating that the key was not recognized.
          process_cache_miss(host_keys, arguments, HostKeyMismatch, "does not match") unless found_keys

          if found_keys.respond_to?(:matches_validity?)
            unless found_keys.matches_validity?(arguments[:key])
              binding.break
              # TODO why not valid?
              process_cache_miss(host_keys, arguments, HostKeyUnknown, "Certificate not valid")
            end
          end

          # If found host_key has principal support (CertAuthority), it must match
          if found_keys.respond_to?(:matches_principal?)
            return true if found_keys.matches_principal?(arguments[:key], host_keys.hostname)

            process_cache_miss(host_keys, arguments, HostKeyUnknown, "Certificate invalid: name is not a listed principal")
          end

          # If we passed all checks, it's verified
          true
        end

        def verify_signature(&block)
          yield
        end

        private

        def process_cache_miss(host_keys, args, exc_class, message)
          exception = exc_class.new("fingerprint #{args[:fingerprint]} " +
                                    "#{message} for #{host_keys.host.inspect}")
          exception.data = args
          exception.callback = Proc.new do
            host_keys.add_host_key(args[:key])
          end
          raise exception
        end
      end
    end
  end
end
