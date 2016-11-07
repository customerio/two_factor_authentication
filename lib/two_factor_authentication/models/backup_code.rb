module Devise
  module Models
    module TwoFactorAuthenticatable
      class BackupCode < ActiveRecord::Base
        attr_accessor :clear_text
      end
    end
  end
end
