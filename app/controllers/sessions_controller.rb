class SessionsController < ApplicationController
  def new
  end
  def create
    email = params[:session][:email]
    password = params[:session][:password]
    user = User.authenticate(email, password)
     
    if user # if authentication was true
      session[:user_id] = user.id
      flash[:notice] =" Welcome, You are logged in."
      redirect_to :root
      
    else
      flash[:error] =" Please, enter correct credentials. Try again !!"
      render :action => "new"
      
    end
  end
  
  
  def destroy
    session[:user_id] = nil
    flash[:notice] = "You are log out, bye bye !! "
    redirect_to :root
    
  end

end
