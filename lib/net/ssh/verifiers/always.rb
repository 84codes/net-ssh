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
          found = host_keys.find do |key|
            if key.respond_to?(:matches_key?)
              key.matches_key?(arguments[:key])
            else
              key.ssh_type == arguments[:key].ssh_type && key.to_blob == arguments[:key].to_blob
            end
          end

          if found && found.respond_to?(:matches_principal?)
            # one.hosts.netssh
            # one.hosts.netssh,127.0.0.1
            # [one.hosts.netssh]:2200
            # [one.hosts.netssh]:2200,[127.0.0.1]:2200
            hostname_to_verify = host_keys.host.split(",").first.gsub(/\[|\]:\d+/, "")
            principal_match = found.matches_principal?(arguments[:key], hostname_to_verify)

            unless principal_match
              process_cache_miss(host_keys, arguments, HostKeyUnknown, "name is not a listed principal")
            end
          end

          # If a match was found, return true. Otherwise, raise an exception
          # indicating that the key was not recognized.
          process_cache_miss(host_keys, arguments, HostKeyMismatch, "does not match") unless found

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
