class User <ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  # Rails 4.1 does not function with 'attr_accessible' so found below online
	def user_params
      params.require(:user).permit(:username, :email, :password, :password_confirmation)
    end
end
