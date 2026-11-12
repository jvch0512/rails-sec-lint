class UsersController < ApplicationController
  skip_before_action :verify_authenticity_token

  def show
    @user = User.where("name = '#{params[:name]}'").first
    render inline: "Hello #{params[:name]}"
  end

  def export
    system("tar czf /tmp/out.tgz #{params[:dir]}")
    redirect_to params[:next]
  end

  def update
    @user.update(params.require(:user).permit!)
    token = rand(100000)
  end
end
