class Post < ActiveRecord::Base
  has_many :comments
  
validates_presence_of :title, :body
  validates_length_of :body, :minimum => 30, :message => "Your message is not enough to to be accepted !"
  validates_length_of :title, :within => 4..30
  
  
  def Post.all_published
    find_all_by_published(true).reverse
  end
end
