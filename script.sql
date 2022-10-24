
CREATE TABLE IF NOT EXISTS advert.user (
  id INT NOT NULL AUTO_INCREMENT,
  username VARCHAR(20) NOT NULL,
  first_name VARCHAR(15) NOT NULL,
  last_name VARCHAR(15) NOT NULL,
  address VARCHAR(60) NOT NULL,
  email VARCHAR(45) NOT NULL,
  phone_number VARCHAR(13) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE INDEX id_UNIQUE (id ASC) VISIBLE)
ENGINE = InnoDB;


CREATE TABLE IF NOT EXISTS advert.category (
  id INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(45) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE INDEX id_UNIQUE (id ASC) VISIBLE,
  UNIQUE INDEX name_UNIQUE (name ASC) VISIBLE)
ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS advert.advertisement (
  id INT NOT NULL AUTO_INCREMENT,
  description VARCHAR(100) NOT NULL,
  status TINYINT NOT NULL,
  category_id INT NOT NULL,
  user_id INT NOT NULL,
  PRIMARY KEY (id),
  UNIQUE INDEX id_UNIQUE (id ASC) VISIBLE,
  INDEX fk_advertisement_category_idx (category_id ASC) VISIBLE,
  INDEX fk_advertisement_user1_idx (user_id ASC) VISIBLE,
  CONSTRAINT fk_advertisement_category
    FOREIGN KEY (category_id)
    REFERENCES advert.category (id)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT fk_advertisement_user1
    FOREIGN KEY (user_id)
    REFERENCES advert.user (id)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
