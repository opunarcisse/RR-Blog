class User < ActiveRecord::Base
  
attr_accessor :password_confirmation
attr_reader :password

validates_uniqueness_of :email
validates_presence_of :password
validates_confirmation_of :password
validates_format_of  :email,
                    :with => /\A([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})\Z/i

  def password=(pwd)
  @password = pwd
  return if pwd.blank?
  create_new_salt
  self.hashed_password = User.encrypted_password(pwd, self.salt)
   
  end
  # Returns user if the supplied email and password match with database
  
  def User.authenticate(email, password)
    user = User.find_by_email(email)
    if user
      password_attempt = User.encrypted_password(password, user.salt)
      if password_attempt != user.hashed_password
        user = nil
      end
    end
    return user
  end
  
  private
  def create_new_salt
    # generates some values and stored intro the databse 
  self.salt = Digest::SHA256.hexdigest(Time.now.to_s + rand.to_s)
  end
  
  def User.encrypted_password(pwd, salt)
    string_to_hash = pwd + salt
    Digest::SHA256.hexdigest(string_to_hash)
  end
  

end
