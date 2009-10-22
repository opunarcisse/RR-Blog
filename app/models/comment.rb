class Comment < ActiveRecord::Base
  belongs_to :post
  
  validates_presence_of :body, :commenter # commenter and body are obligatory
  validates_length_of :body, :within => 10..3000 # lenght of the comments body
  validates_uniqueness_of :body, :scope => :commenter # can not add same comments
end
