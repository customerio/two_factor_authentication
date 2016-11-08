require 'two_factor_authentication/hooks/two_factor_authenticatable'
require 'rotp'
require 'encryptor'

module Devise
  module Models
    module TwoFactorAuthenticatable
      extend ActiveSupport::Concern

      module ClassMethods
        def has_one_time_password(options = {})
          include InstanceMethodsOnActivation
          include EncryptionInstanceMethods if options[:encrypted] == true
        end

        ::Devise::Models.config(
          self, :max_login_attempts, :allowed_otp_drift_seconds, :otp_length,
          :remember_otp_session_for_seconds, :otp_secret_encryption_key,
          :direct_otp_length, :direct_otp_valid_for, :totp_timestamp,
          :totp_delay, :totp_delay_per_attempt, :totp_delay_max,
          :use_backup_codes, :backup_code_length, :backup_code_amount)
      end

      module InstanceMethodsOnActivation
        def authenticate_otp(code, options = {})
          if self.class.use_backup_codes && backup_codes_enabled? && authenticate_backup_code(code)
            return true
          end
          return true if direct_otp && authenticate_direct_otp(code)
          return true if totp_enabled? && authenticate_totp(code, options)
          false
        end

        def authenticate_backup_code(code)
          return false if backup_codes.empty?
          backup = backup_codes.find do |c|
            ActiveSupport::SecurityUtils.secure_compare(c.clear_text,code)
          end
          return false if backup.nil?
          backup.destroy!
          true
        end

        def authenticate_direct_otp(code)
          return false if direct_otp.nil? || direct_otp != code || direct_otp_expired?
          clear_direct_otp
          true
        end

        def authenticate_totp(code, options = {})
          totp_secret = options[:otp_secret_key] || otp_secret_key
          digits = options[:otp_length] || self.class.otp_length
          drift = options[:drift] || self.class.allowed_otp_drift_seconds
          raise "authenticate_totp called with no otp_secret_key set" if totp_secret.nil?
          totp = ROTP::TOTP.new(totp_secret, digits: digits)
          new_timestamp = totp.verify_with_drift_and_prior(code, drift, totp_timestamp)

          # Delay after validating to throttle attempts
          delay = self.class.totp_delay + (self.second_factor_attempts_count || 0) * self.class.totp_delay_per_attempt
          sleep [delay, self.class.totp_delay_max].min

          return false unless new_timestamp
          self.totp_timestamp = new_timestamp
          true
        end

        def provisioning_uri(account = nil, options = {})
          totp_secret = options[:otp_secret_key] || otp_secret_key
          options[:digits] ||= options[:otp_length] || self.class.otp_length
          raise "provisioning_uri called with no otp_secret_key set" if totp_secret.nil?
          account ||= email if respond_to?(:email)
          ROTP::TOTP.new(totp_secret, options).provisioning_uri(account)
        end

        def need_two_factor_authentication?(request)
          true
        end

        def send_new_otp(options = {})
          create_direct_otp options
          send_two_factor_authentication_code(direct_otp)
        end

        def send_two_factor_authentication_code(code)
          raise NotImplementedError.new("No default implementation - please define in your class.")
        end

        def max_login_attempts?
          second_factor_attempts_count.to_i >= max_login_attempts.to_i
        end

        def max_login_attempts
          self.class.max_login_attempts
        end

        def increment_second_factor_attempts_count!
          self.class.where(id: id).update_all('second_factor_attempts_count = second_factor_attempts_count + 1')
        end

        def totp_enabled?
          respond_to?(:otp_secret_key) && !otp_secret_key.nil?
        end

        def backup_codes_enabled?
          respond_to?(:backup_codes) && !backup_codes.empty?
        end

        def confirm_totp_secret(secret, code, options = {})
          return false unless authenticate_totp(code, {otp_secret_key: secret})
          self.otp_secret_key = secret
          true
        end

        def generate_totp_secret
          ROTP::Base32.random_base32
        end

        def create_direct_otp(options = {})
          # Create a new random OTP and store it in the database
          digits = options[:length] || self.class.direct_otp_length || 6
          update_attributes(
            direct_otp: random_base10(digits),
            direct_otp_sent_at: Time.now.utc
          )
        end

        def create_backup_codes!
          destroy_backup_codes
          self.class.backup_code_amount.times do
            BackupCode.create!({
              user_id: id,
              code: encrypt(ROTP::Base32.random_base32(self.class.backup_code_length))
            })
          end
        end

        def destroy_backup_codes
          BackupCode.where(user_id: id).destroy_all
        end

        private

        def random_base10(digits)
          SecureRandom.random_number(10**digits).to_s.rjust(digits, '0')
        end

        def direct_otp_expired?
          Time.now.utc > direct_otp_sent_at + self.class.direct_otp_valid_for
        end

        def clear_direct_otp
          update_attributes(direct_otp: nil, direct_otp_sent_at: nil)
        end
      end

      module EncryptionInstanceMethods
        def otp_secret_key
          decrypt(encrypted_otp_secret_key)
        end

        def otp_secret_key=(value)
          self.encrypted_otp_secret_key = encrypt(value)
        end

        def backup_codes
          BackupCode.where(user_id: id).each do |backup|
            backup.clear_text = decrypt(backup.code)
          end
        end

        private

        def decrypt(encrypted_value)
          return encrypted_value if encrypted_value.blank?

          encrypted_value = encrypted_value.unpack('m').first

          value = ::Encryptor.decrypt(encryption_options_for(encrypted_value))

          if defined?(Encoding)
            encoding = Encoding.default_internal || Encoding.default_external
            value = value.force_encoding(encoding.name)
          end

          value
        end

        def encrypt(value)
          return value if value.blank?

          value = value.to_s
          encrypted_value = ::Encryptor.encrypt(encryption_options_for(value))

          encrypted_value = [encrypted_value].pack('m')

          encrypted_value
        end

        def encryption_options_for(value)
          {
            value: value,
            key: Devise.otp_secret_encryption_key,
            iv: iv_for_attribute,
            salt: salt_for_attribute
          }
        end

        def iv_for_attribute(algorithm = 'aes-256-cbc')
          iv = encrypted_otp_secret_key_iv

          if iv.nil?
            algo = OpenSSL::Cipher::Cipher.new(algorithm)
            iv = [algo.random_iv].pack('m')
            self.encrypted_otp_secret_key_iv = iv
          end

          iv.unpack('m').first if iv.present?
        end

        def salt_for_attribute
          salt = encrypted_otp_secret_key_salt ||
                 self.encrypted_otp_secret_key_salt = generate_random_base64_encoded_salt

          decode_salt_if_encoded(salt)
        end

        def generate_random_base64_encoded_salt
          prefix = '_'
          prefix + [SecureRandom.random_bytes].pack('m')
        end

        def decode_salt_if_encoded(salt)
          salt.slice(0).eql?('_') ? salt.slice(1..-1).unpack('m').first : salt
        end
      end
    end
  end
end
